import json
import subprocess
import sys
from pathlib import Path

try:
    from controller.alert_state import (
        is_alert_processed,
        save_selected_alert,
    )
    from controller.iap_helpers import (
        run_target_command,
        run_wazuh_command,
    )
except ModuleNotFoundError:
    from alert_state import (
        is_alert_processed,
        save_selected_alert,
    )
    from iap_helpers import (
        run_target_command,
        run_wazuh_command,
    )


SERVICE_PATH = (
    "/etc/systemd/system/"
    "thesis-persistence.service"
)
SCRIPT_PATH = "/usr/local/bin/thesis-persistence.sh"

TARGET_AGENT_NAME = "thesis-self-healing-vm"
SCENARIO = "malicious_systemd_persistence"


def target_persistence_exists():
    state_file = (
        Path(__file__).resolve().parents[1]
        / "controller"
        / "ssh_rotation_state.json"
    )

    state = json.loads(
        state_file.read_text(encoding="utf-8")
    )

    private_key = Path(state["new_private_key"])

    remote_command = (
        f"service_file=$(test -f {SERVICE_PATH} "
        "&& echo PRESENT || echo ABSENT); "
        f"script_file=$(test -f {SCRIPT_PATH} "
        "&& echo PRESENT || echo ABSENT); "
        "service_active=$(sudo systemctl is-active "
        "thesis-persistence.service 2>/dev/null || true); "
        "printf '%s|%s|%s\n' "
        '"$service_file" "$script_file" "$service_active"'
    )

    proxy_command = (
        "gcloud.cmd compute start-iap-tunnel "
        "thesis-self-healing-vm %p "
        "--listen-on-stdin "
        "--zone=europe-west1-b "
        "--project=project-207ee30d-2273-45b0-8a0"
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
        "thesisadmin@thesis-self-healing-vm",
        remote_command,
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        subprocess.run(
            [
                "taskkill",
                "/PID", str(process.pid),
                "/T",
                "/F",
            ],
            capture_output=True,
            text=True,
        )

    output = stdout.strip()

    print(f"[TARGET STATE] {output}")

    return "PRESENT|PRESENT|active" in output


def unprocessed_wazuh_alert_exists():
    remote_command = (
        "sudo grep -F "
        f"'{SERVICE_PATH}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(remote_command)

    if not result["stdout"]:
        print("[NO WAZUH SYSTEMD ALERT FOUND]")
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

        syscheck = alert.get("syscheck", {})
        path = syscheck.get("path")
        event = syscheck.get("event")

        groups = alert.get(
            "rule",
            {},
        ).get("groups", [])

        if (
            alert_id
            and agent_name == TARGET_AGENT_NAME
            and path == SERVICE_PATH
            and event in {"added", "modified"}
            and "syscheck" in groups
        ):
            matching_alerts.append(alert)

    if not matching_alerts:
        print(
            "[NO MATCHING WAZUH SYSTEMD "
            "FIM ALERT FOUND]"
        )
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(
        SCENARIO,
        alert_id,
    ):
        print(
            "[ALREADY PROCESSED] Systemd alert "
            f"ID {alert_id} has already completed "
            "recovery."
        )
        return False

    save_selected_alert(
        SCENARIO,
        alert_id,
    )

    print(
        "[UNPROCESSED WAZUH SYSTEMD "
        "ALERT FOUND]"
    )
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(latest_alert))

    return True


def recoverable_alert_exists():
    if not unprocessed_wazuh_alert_exists():
        return False

    print(
        "[2] Confirming malicious systemd "
        "persistence is active..."
    )

    if target_persistence_exists():
        print(
            "[CONFIRMED] Malicious systemd "
            "persistence is active."
        )
        return True

    print(
        "[NO ACTION] An unprocessed alert exists, "
        "but active systemd persistence was not "
        "confirmed."
    )
    return False


def main():
    check_only = "--check-only" in sys.argv

    print(
        "[1] Checking Wazuh for an unprocessed "
        "systemd-persistence alert..."
    )

    if not recoverable_alert_exists():
        print(
            "[STOP] No active unprocessed systemd "
            "persistence requires recovery."
        )
        return 1

    if check_only:
        print(
            "[CHECK ONLY] Active recoverable "
            "systemd persistence confirmed."
        )
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
