import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from controller.iap_helpers import run_wazuh_command


# --- Local paths and target connection settings ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"

# Controlled runtime-listener values used by detection and evidence checks.
PORT = 4444
RULE_ID = "100120"
ALERT_LOCATION = "thesis unexpected listener"


# --- Load the current trusted key used to access the target ---
def get_current_private_key():
    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8-sig")
    )

    private_key = Path(state["new_private_key"])

    if not private_key.exists():
        raise FileNotFoundError(
            f"Current trusted key not found: {private_key}"
        )

    return private_key


# --- Collect target-side evidence for the active listener and its artefacts ---
def run_remote_evidence_command(private_key):
    # The script captures identity, socket state, PID, process command/executable
    # and log artefact, then emits explicit PASS/FAIL markers for each item.
    remote_command = rf'''
PID_FILE=/var/tmp/thesis-unexpected-listener.pid
LOG_FILE=/var/tmp/thesis-unexpected-listener.log

echo "=== TIMESTAMP UTC ==="
date -u --iso-8601=seconds

echo
echo "=== TARGET IDENTITY ==="
hostname
hostname -I

echo
echo "=== LISTENER PORT {PORT} ==="
ss -H -lntp 'sport = :{PORT}' || true

echo
echo "=== PID FILE ==="
sudo cat "$PID_FILE" 2>/dev/null || true

listener_pid="$(
    sudo cat "$PID_FILE" 2>/dev/null || true
)"

echo
echo "=== PROCESS DETAILS ==="
if test -n "$listener_pid" \
    && sudo test -r "/proc/$listener_pid/cmdline"; then
    ps -fp "$listener_pid" || true

    echo
    echo "--- COMMAND LINE ---"
    sudo tr '\0' ' ' < "/proc/$listener_pid/cmdline" || true
    echo

    echo
    echo "--- EXECUTABLE ---"
    sudo readlink -f "/proc/$listener_pid/exe" || true
fi

echo
echo "=== ATTACK ARTIFACTS ==="
sudo ls -la "$PID_FILE" "$LOG_FILE" 2>/dev/null || true

echo
echo "=== LISTENER LOG ==="
sudo tail -n 50 "$LOG_FILE" 2>/dev/null || true

echo
echo "=== EVIDENCE ITEM STATUS ==="

if test "$(hostname)" = "{TARGET_HOST}"; then
    echo "EVIDENCE_TARGET_IDENTITY=PASS"
else
    echo "EVIDENCE_TARGET_IDENTITY=FAIL"
fi

if ss -H -lnt 'sport = :{PORT}' | grep -q .; then
    echo "EVIDENCE_LISTENING_PORT=PASS"
else
    echo "EVIDENCE_LISTENING_PORT=FAIL"
fi

if sudo test -s "$PID_FILE"; then
    echo "EVIDENCE_PID_FILE=PASS"
else
    echo "EVIDENCE_PID_FILE=FAIL"
fi

if test -n "$listener_pid" \
    && sudo test -r "/proc/$listener_pid/cmdline" \
    && sudo tr '\0' ' ' < "/proc/$listener_pid/cmdline" \
       | grep -Fq "python3 -m http.server {PORT}"; then
    echo "EVIDENCE_PROCESS_COMMAND=PASS"
else
    echo "EVIDENCE_PROCESS_COMMAND=FAIL"
fi

if test -n "$listener_pid" \
    && sudo test -e "/proc/$listener_pid/exe" \
    && test -n "$(
        sudo readlink -f "/proc/$listener_pid/exe" 2>/dev/null
    )"; then
    echo "EVIDENCE_PROCESS_EXECUTABLE=PASS"
else
    echo "EVIDENCE_PROCESS_EXECUTABLE=FAIL"
fi

if sudo test -f "$LOG_FILE"; then
    echo "EVIDENCE_LOG_FILE=PASS"
else
    echo "EVIDENCE_LOG_FILE=FAIL"
fi
'''

    # Use the current trusted SSH key through an IAP tunnel.
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
        remote_command,
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
        stdout, stderr = process.communicate(timeout=45)

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        # Clean up a hung Windows SSH/IAP process tree.
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

    return stdout, stderr


# --- Find the exact Wazuh command-monitoring alert for port 4444 ---
def get_matching_wazuh_alert():
    # Search both current and compressed Wazuh alert logs for the explicit marker.
    command = (
        "sudo grep -F "
        f"'THESIS_UNEXPECTED_LISTENER port={PORT}' "
        "/var/ossec/logs/alerts/alerts.json "
        "2>/dev/null || true; "
        "sudo find /var/ossec/logs/alerts "
        "-type f -name 'ossec-alerts-*.json.gz' "
        "-exec zgrep -h -F "
        f"'THESIS_UNEXPECTED_LISTENER port={PORT}' "
        "{} + 2>/dev/null || true"
    )

    result = run_wazuh_command(command)

    # De-duplicate by alert ID before choosing the newest matching event.
    matching_alerts = {}

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert_id = str(alert.get("id", ""))
        rule_id = str(
            alert.get("rule", {}).get("id", "")
        )

        if (
            alert_id
            and alert.get("agent", {}).get("name")
            == TARGET_HOST
            and rule_id == RULE_ID
            and alert.get("location") == ALERT_LOCATION
            and f"THESIS_UNEXPECTED_LISTENER port={PORT}"
            in alert.get("full_log", "")
        ):
            matching_alerts[alert_id] = alert

    if not matching_alerts:
        return result, ""

    newest_alert = max(
        matching_alerts.values(),
        key=lambda alert: alert.get("timestamp", ""),
    )

    return result, json.dumps(newest_alert)


# --- Save evidence and enforce the seven-item listener evidence gate ---
def main():
    print(
        "[INFO] Capturing unexpected-listener evidence..."
    )

    private_key = get_current_private_key()

    stdout, stderr = run_remote_evidence_command(
        private_key
    )

    alert_result, matching_alert = (
        get_matching_wazuh_alert()
    )

    # Six target-side items plus one matching Wazuh alert = seven required items.
    target_evidence_markers = [
        "EVIDENCE_TARGET_IDENTITY=PASS",
        "EVIDENCE_LISTENING_PORT=PASS",
        "EVIDENCE_PID_FILE=PASS",
        "EVIDENCE_PROCESS_COMMAND=PASS",
        "EVIDENCE_PROCESS_EXECUTABLE=PASS",
        "EVIDENCE_LOG_FILE=PASS",
    ]

    evidence_items_required = (
        len(target_evidence_markers) + 1
    )

    evidence_items_captured = sum(
        marker in stdout
        for marker in target_evidence_markers
    )

    if matching_alert:
        evidence_items_captured += 1

    # Checklist completeness is scenario-specific, not a universal forensic score.
    evidence_completeness_percentage = round(
        (
            evidence_items_captured
            / evidence_items_required
        )
        * 100,
        2,
    )

    print(
        "[METRIC] evidence_items_required = "
        f"{evidence_items_required}"
    )
    print(
        "[METRIC] evidence_items_captured = "
        f"{evidence_items_captured}"
    )
    print(
        "[METRIC] evidence_completeness_percentage = "
        f"{evidence_completeness_percentage}"
    )

    EVIDENCE_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    evidence_file = (
        EVIDENCE_DIR
        / (
            "unexpected_listener_pre_replacement_"
            f"{timestamp}.txt"
        )
    )

    # Preserve raw evidence regardless of whether the later gate passes.
    content = (
        "UNEXPECTED LISTENER EVIDENCE\n"
        "CAPTURED BEFORE TERRAFORM REPLACEMENT\n"
        "=====================================\n\n"
        f"{stdout}\n"
        "\n=== MATCHING WAZUH LISTENER ALERT ===\n"
        f"{matching_alert or 'MATCHING_ALERT_NOT_FOUND'}\n"
        "\n=== EVIDENCE COMPLETENESS ===\n"
        f"evidence_items_required="
        f"{evidence_items_required}\n"
        f"evidence_items_captured="
        f"{evidence_items_captured}\n"
        f"evidence_completeness_percentage="
        f"{evidence_completeness_percentage}\n"
    )

    if stderr:
        content += (
            "\n=== TARGET SSH/IAP STDERR ===\n"
            f"{stderr}\n"
        )

    if alert_result["stderr"]:
        content += (
            "\n=== WAZUH MANAGER STDERR ===\n"
            f"{alert_result['stderr']}\n"
        )

    evidence_file.write_text(
        content,
        encoding="utf-8",
    )

    # Missing evidence stops the workflow before destructive recovery.
    if (
        evidence_items_captured
        != evidence_items_required
    ):
        print(
            f"[INFO] Partial evidence saved to: "
            f"{evidence_file}"
        )
        print(
            "[FAIL] Required unexpected-listener "
            "evidence was incomplete."
        )
        return 1

    print(
        f"[SUCCESS] Evidence captured: "
        f"{evidence_file}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
