import base64
import json
import subprocess
import sys
from pathlib import Path

try:
    from controller.alert_state import (
        is_alert_processed,
        save_selected_alert,
    )
    from controller.iap_helpers import run_wazuh_command
except ModuleNotFoundError:
    from alert_state import (
        is_alert_processed,
        save_selected_alert,
    )
    from iap_helpers import run_wazuh_command


TARGET_AGENT_NAME = "thesis-self-healing-vm"
SCENARIO = "unexpected_listener"
PORT = 4444
RULE_ID = "100120"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"


def get_current_private_key():
    state_file = (
        Path(__file__).resolve().parents[1]
        / "controller"
        / "ssh_rotation_state.json"
    )

    state = json.loads(
        state_file.read_text(encoding="utf-8-sig")
    )

    private_key = Path(state["new_private_key"])

    if not private_key.exists():
        raise FileNotFoundError(
            f"Current SSH private key not found: {private_key}"
        )

    return private_key


def target_listener_exists():
    private_key = get_current_private_key()

    check_script = rf"""set -u

if ss -H -lnt 'sport = :{PORT}' | grep -q .; then
    port_state=PRESENT
else
    port_state=ABSENT
fi

process_state=PROCESS_ABSENT
pid_file=/var/tmp/thesis-unexpected-listener.pid

if sudo test -f "$pid_file"; then
    listener_pid=$(sudo cat "$pid_file" 2>/dev/null || true)

    if [ -n "$listener_pid" ] && sudo test -r "/proc/$listener_pid/cmdline"; then
        process_command=$(
            sudo tr '\0' ' ' < "/proc/$listener_pid/cmdline"
        )

        case "$process_command" in
            *"python3 -m http.server {PORT}"*)
                process_state=PROCESS_PRESENT
                ;;
        esac
    fi
fi

printf '%s|%s\n' "$port_state" "$process_state"
echo TARGET_LISTENER_CHECK_COMPLETE
"""

    encoded = base64.b64encode(
        check_script.encode("utf-8")
    ).decode("ascii")

    proxy_command = (
        "gcloud.cmd compute start-iap-tunnel "
        f"{TARGET_HOST} %p "
        "--listen-on-stdin "
        f"--zone={ZONE} "
        f"--project={PROJECT_ID}"
    )

    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=15",
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", str(private_key),
        "-o", f"ProxyCommand={proxy_command}",
        f"{TARGET_USER}@{TARGET_HOST}",
        f"echo {encoded} | base64 -d | bash",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    try:
        stdout, stderr = process.communicate(timeout=60)

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(
                "utf-8",
                errors="replace",
            )

        if isinstance(stderr, bytes):
            stderr = stderr.decode(
                "utf-8",
                errors="replace",
            )

        subprocess.run(
            [
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
            ],
            capture_output=True,
            text=True,
        )

    output = stdout.strip()

    state_line = next(
        (
            line
            for line in output.splitlines()
            if "|" in line
        ),
        "",
    )

    print(f"[TARGET STATE] {state_line}")

    return (
        "PRESENT|PROCESS_PRESENT" in output
        and "TARGET_LISTENER_CHECK_COMPLETE" in output
    )


def unprocessed_wazuh_alert_exists():
    remote_command = (
        "sudo grep -F "
        f"'\"id\":\"{RULE_ID}\"' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(remote_command)

    if not result["stdout"]:
        print("[NO WAZUH LISTENER ALERT FOUND]")
        return False

    matching_alerts = []

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert_id = str(alert.get("id", ""))

        agent_name = alert.get(
            "agent",
            {},
        ).get("name")

        rule_id = str(
            alert.get(
                "rule",
                {},
            ).get("id", "")
        )

        location = alert.get("location", "")
        full_log = alert.get("full_log", "")

        if (
            alert_id
            and agent_name == TARGET_AGENT_NAME
            and rule_id == RULE_ID
            and location == "thesis unexpected listener"
            and "THESIS_UNEXPECTED_LISTENER port=4444"
            in full_log
        ):
            matching_alerts.append(alert)

    if not matching_alerts:
        print(
            "[NO MATCHING WAZUH UNEXPECTED "
            "LISTENER ALERT FOUND]"
        )
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(
        SCENARIO,
        alert_id,
    ):
        print(
            "[ALREADY PROCESSED] Listener alert "
            f"ID {alert_id} has already completed "
            "recovery."
        )
        return False

    save_selected_alert(
        SCENARIO,
        alert_id,
    )

    print(
        "[UNPROCESSED WAZUH LISTENER ALERT FOUND]"
    )
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(latest_alert))

    return True


def recoverable_alert_exists():
    if not unprocessed_wazuh_alert_exists():
        return False

    print(
        "[2] Confirming unexpected listener "
        f"on port {PORT} is active..."
    )

    if target_listener_exists():
        print(
            "[CONFIRMED] Unexpected listener "
            f"on port {PORT} is active."
        )
        return True

    print(
        "[NO ACTION] An unprocessed alert exists, "
        "but the active listener was not confirmed."
    )
    return False


def main():
    check_only = "--check-only" in sys.argv

    print(
        "[1] Checking Wazuh for an unprocessed "
        "unexpected-listener alert..."
    )

    if not recoverable_alert_exists():
        print(
            "[STOP] No active unprocessed listener "
            "requires recovery."
        )
        return 1

    if check_only:
        print(
            "[CHECK ONLY] Active recoverable "
            "unexpected listener confirmed."
        )
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())