import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from controller.iap_helpers import run_wazuh_command


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"


def get_current_private_key():
    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8")
    )

    private_key = Path(state["new_private_key"])

    if not private_key.exists():
        raise FileNotFoundError(
            f"Current trusted key not found: {private_key}"
        )

    return private_key


def run_remote_evidence_command(private_key):
    remote_command = r'''
echo "=== TIMESTAMP UTC ==="
date -u --iso-8601=seconds

echo
echo "=== HOST ==="
hostname
whoami

echo
echo "=== SERVICE FILE ==="
sudo ls -la /etc/systemd/system/thesis-persistence.service
sudo cat /etc/systemd/system/thesis-persistence.service

echo
echo "=== MALICIOUS SCRIPT ==="
sudo ls -la /usr/local/bin/thesis-persistence.sh
sudo cat /usr/local/bin/thesis-persistence.sh

echo
echo "=== SERVICE ENABLED STATE ==="
sudo systemctl is-enabled thesis-persistence.service || true

echo
echo "=== SERVICE ACTIVE STATE ==="
sudo systemctl is-active thesis-persistence.service || true

echo
echo "=== SERVICE STATUS ==="
sudo systemctl status thesis-persistence.service --no-pager || true

echo
echo "=== ENABLEMENT SYMLINK ==="
sudo ls -la /etc/systemd/system/multi-user.target.wants/thesis-persistence.service || true

echo
echo "=== RUNNING PROCESS ==="
sudo pgrep -a -f thesis-persistence || true

echo
echo "=== HEARTBEAT EVIDENCE ==="
sudo tail -n 10 /var/tmp/thesis-systemd-heartbeat.log || true

echo
echo "=== FILE HASHES ==="
sudo sha256sum \
  /etc/systemd/system/thesis-persistence.service \
  /usr/local/bin/thesis-persistence.sh || true

echo
echo "=== EVIDENCE ITEM STATUS ==="

if test "$(hostname)" = "thesis-self-healing-vm"; then
  echo "EVIDENCE_TARGET_IDENTITY=PASS"
else
  echo "EVIDENCE_TARGET_IDENTITY=FAIL"
fi

if sudo test -s /etc/systemd/system/thesis-persistence.service; then
  echo "EVIDENCE_SERVICE_FILE=PASS"
else
  echo "EVIDENCE_SERVICE_FILE=FAIL"
fi

if sudo test -s /usr/local/bin/thesis-persistence.sh; then
  echo "EVIDENCE_SCRIPT_FILE=PASS"
else
  echo "EVIDENCE_SCRIPT_FILE=FAIL"
fi

if sudo systemctl is-enabled --quiet thesis-persistence.service; then
  echo "EVIDENCE_SERVICE_ENABLED=PASS"
else
  echo "EVIDENCE_SERVICE_ENABLED=FAIL"
fi

if sudo systemctl is-active --quiet thesis-persistence.service; then
  echo "EVIDENCE_SERVICE_ACTIVE=PASS"
else
  echo "EVIDENCE_SERVICE_ACTIVE=FAIL"
fi

if sudo test -L /etc/systemd/system/multi-user.target.wants/thesis-persistence.service; then
  echo "EVIDENCE_ENABLEMENT_SYMLINK=PASS"
else
  echo "EVIDENCE_ENABLEMENT_SYMLINK=FAIL"
fi

main_pid="$(sudo systemctl show \
  --property=MainPID \
  --value \
  thesis-persistence.service 2>/dev/null || echo 0)"

if test "${main_pid:-0}" -gt 0 2>/dev/null \
  && sudo kill -0 "$main_pid" 2>/dev/null; then
  echo "EVIDENCE_RUNNING_PROCESS=PASS"
else
  echo "EVIDENCE_RUNNING_PROCESS=FAIL"
fi

if sudo test -s /var/tmp/thesis-systemd-heartbeat.log; then
  echo "EVIDENCE_HEARTBEAT=PASS"
else
  echo "EVIDENCE_HEARTBEAT=FAIL"
fi

if sudo sha256sum \
  /etc/systemd/system/thesis-persistence.service \
  /usr/local/bin/thesis-persistence.sh \
  >/dev/null 2>&1; then
  echo "EVIDENCE_FILE_HASHES=PASS"
else
  echo "EVIDENCE_FILE_HASHES=FAIL"
fi

echo
echo "=== EVIDENCE ITEM STATUS ==="

if test "$(hostname)" = "thesis-self-healing-vm"; then
  echo "EVIDENCE_TARGET_IDENTITY=PASS"
else
  echo "EVIDENCE_TARGET_IDENTITY=FAIL"
fi

if sudo test -s /etc/systemd/system/thesis-persistence.service; then
  echo "EVIDENCE_SERVICE_FILE=PASS"
else
  echo "EVIDENCE_SERVICE_FILE=FAIL"
fi

if sudo test -s /usr/local/bin/thesis-persistence.sh; then
  echo "EVIDENCE_SCRIPT_FILE=PASS"
else
  echo "EVIDENCE_SCRIPT_FILE=FAIL"
fi

if sudo systemctl is-enabled --quiet thesis-persistence.service; then
  echo "EVIDENCE_SERVICE_ENABLED=PASS"
else
  echo "EVIDENCE_SERVICE_ENABLED=FAIL"
fi

if sudo systemctl is-active --quiet thesis-persistence.service; then
  echo "EVIDENCE_SERVICE_ACTIVE=PASS"
else
  echo "EVIDENCE_SERVICE_ACTIVE=FAIL"
fi

if sudo test -L /etc/systemd/system/multi-user.target.wants/thesis-persistence.service; then
  echo "EVIDENCE_ENABLEMENT_SYMLINK=PASS"
else
  echo "EVIDENCE_ENABLEMENT_SYMLINK=FAIL"
fi

main_pid="$(sudo systemctl show \
  --property=MainPID \
  --value \
  thesis-persistence.service 2>/dev/null || echo 0)"

if test "${main_pid:-0}" -gt 0 2>/dev/null \
  && sudo kill -0 "$main_pid" 2>/dev/null; then
  echo "EVIDENCE_RUNNING_PROCESS=PASS"
else
  echo "EVIDENCE_RUNNING_PROCESS=FAIL"
fi

if sudo test -s /var/tmp/thesis-systemd-heartbeat.log; then
  echo "EVIDENCE_HEARTBEAT=PASS"
else
  echo "EVIDENCE_HEARTBEAT=FAIL"
fi

if sudo sha256sum \
  /etc/systemd/system/thesis-persistence.service \
  /usr/local/bin/thesis-persistence.sh \
  >/dev/null 2>&1; then
  echo "EVIDENCE_FILE_HASHES=PASS"
else
  echo "EVIDENCE_FILE_HASHES=FAIL"
fi
'''

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


def get_matching_wazuh_alert():
    service_path = (
        "/etc/systemd/system/"
        "thesis-persistence.service"
    )

    command = (
        "sudo grep -F "
        f"'{service_path}' "
        "/var/ossec/logs/alerts/alerts.json "
        "2>/dev/null || true; "
        "sudo find /var/ossec/logs/alerts "
        "-type f -name 'ossec-alerts-*.json.gz' "
        "-exec zgrep -h -F "
        f"'{service_path}' "
        "{} + 2>/dev/null || true"
    )

    result = run_wazuh_command(command)

    matching_alerts = {}

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert_id = str(alert.get("id", ""))

        if (
            alert_id
            and alert.get("location") == "syscheck"
            and alert.get("agent", {}).get("name")
            == TARGET_HOST
            and alert.get("syscheck", {}).get("path")
            == service_path
            and alert.get("syscheck", {}).get("event")
            in {"added", "modified"}
        ):
            matching_alerts[alert_id] = alert

    if not matching_alerts:
        return result, ""

    newest_alert = max(
        matching_alerts.values(),
        key=lambda alert: alert.get("timestamp", ""),
    )

    return result, json.dumps(newest_alert)

def main():
    print(
        "[INFO] Capturing malicious systemd "
        "persistence evidence..."
    )

    private_key = get_current_private_key()

    stdout, stderr = run_remote_evidence_command(
        private_key
    )

    alert_result, matching_alert = (
        get_matching_wazuh_alert()
    )

    target_evidence_markers = [
        "EVIDENCE_TARGET_IDENTITY=PASS",
        "EVIDENCE_SERVICE_FILE=PASS",
        "EVIDENCE_SCRIPT_FILE=PASS",
        "EVIDENCE_SERVICE_ENABLED=PASS",
        "EVIDENCE_SERVICE_ACTIVE=PASS",
        "EVIDENCE_ENABLEMENT_SYMLINK=PASS",
        "EVIDENCE_RUNNING_PROCESS=PASS",
        "EVIDENCE_HEARTBEAT=PASS",
        "EVIDENCE_FILE_HASHES=PASS",
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

    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    evidence_file = (
        EVIDENCE_DIR
        / (
            "systemd_persistence_pre_replacement_"
            f"{timestamp}.txt"
        )
    )

    content = (
        "MALICIOUS SYSTEMD PERSISTENCE EVIDENCE\n"
        "CAPTURED BEFORE TERRAFORM REPLACEMENT\n"
        "========================================\n\n"
        f"{stdout}\n"
        "\n=== MATCHING WAZUH SYSCHECK ALERT ===\n"
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

    if (
        evidence_items_captured
        != evidence_items_required
    ):
        print(
            f"[INFO] Partial evidence saved to: "
            f"{evidence_file}"
        )
        print(
            "[FAIL] Required systemd persistence "
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
