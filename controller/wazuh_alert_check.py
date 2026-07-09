import json
import subprocess
import sys
from datetime import datetime, timezone

from iap_helpers import run_wazuh_command


ATTACK_PATH = "/etc/cron.d/realtime_evil_persistence"
TARGET_AGENT_NAME = "thesis-self-healing-vm"
RECENT_WINDOW_SECONDS = 300


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.returncode, result.stdout.strip(), result.stderr.strip()


def parse_wazuh_timestamp(timestamp_text):
    """
    Converts Wazuh timestamp format into a Python datetime.

    Example:
    2026-07-09T19:04:55.748+0000
    """
    return datetime.strptime(timestamp_text, "%Y-%m-%dT%H:%M:%S.%f%z")


def is_recent_alert(alert_timestamp):
    now = datetime.now(timezone.utc)
    age_seconds = (now - alert_timestamp.astimezone(timezone.utc)).total_seconds()

    return 0 <= age_seconds <= RECENT_WINDOW_SECONDS


def wazuh_alert_exists():
    remote_command = "sudo tail -n 500 /var/ossec/logs/alerts/alerts.json || true"

    result = run_wazuh_command(remote_command)

    if not result["stdout"]:
        print("[NO WAZUH ALERT FOUND]")
        return False

    matching_alerts = []

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        timestamp_text = alert.get("timestamp")
        agent_name = alert.get("agent", {}).get("name")
        syscheck = alert.get("syscheck", {})
        path = syscheck.get("path")
        event = syscheck.get("event")
        groups = alert.get("rule", {}).get("groups", [])

        if not timestamp_text:
            continue

        try:
            alert_time = parse_wazuh_timestamp(timestamp_text)
        except ValueError:
            continue

        if (
            agent_name == TARGET_AGENT_NAME
            and path == ATTACK_PATH
            and event == "added"
            and "syscheck" in groups
            and is_recent_alert(alert_time)
        ):
            matching_alerts.append(alert)

    if matching_alerts:
        latest_alert = matching_alerts[-1]
        print("[FRESH WAZUH ALERT FOUND]")
        print(json.dumps(latest_alert))
        return True

    print("[NO FRESH WAZUH ALERT FOUND]")
    print(f"[INFO] Ignoring older matching alerts outside {RECENT_WINDOW_SECONDS} seconds.")
    return False


def run_recovery_controller():
    print("[ACTION] Running cron self-healing controller...")

    command = [
        sys.executable,
        "controller/cron_self_heal.py"
    ]

    code, stdout, stderr = run_command(command)

    if stdout:
        print(stdout)

    if stderr:
        print(stderr)

    return code == 0


def main():
    print("[1] Checking Wazuh alerts for fresh cron persistence through IAP...")

    if not wazuh_alert_exists():
        print("[STOP] No fresh matching Wazuh alert found. Recovery not triggered.")
        return 1

    print("[2] Fresh Wazuh alert confirmed. Triggering recovery...")

    if run_recovery_controller():
        print("[DONE] Alert-driven recovery workflow completed.")
        return 0

    print("[ERROR] Recovery controller failed.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
