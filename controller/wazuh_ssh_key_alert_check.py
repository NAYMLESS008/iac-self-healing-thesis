import json
import time
import sys

from controller.iap_helpers import run_wazuh_command, run_target_command


TARGET_AGENT_NAME = "thesis-self-healing-vm"
AUTHORIZED_KEYS_PATH = "/home/thesisadmin/.ssh/authorized_keys"
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
RECENT_WINDOW_SECONDS = 300


def parse_wazuh_timestamp(timestamp):
    # Example: 2026-07-16T20:30:07.757+0000
    try:
        from datetime import datetime
        return datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%S.%f%z").timestamp()
    except Exception:
        return 0


def old_key_is_active():
    import subprocess

    result = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "thesis-target-old-compromised-key",
            "whoami && hostname"
        ],
        capture_output=True,
        text=True
    )

    return result.returncode == 0 and "thesisadmin" in result.stdout


def main():
    print("[INFO] Checking Wazuh alerts for authorized_keys modification...")

    command = f"sudo grep -i authorized_keys {ALERTS_FILE} | tail -n 50"
    result = run_wazuh_command(command)

    if not result["success"]:
        print("[ERROR] Could not read Wazuh alerts.")
        print(result["stderr"])
        return 1

    now = time.time()
    matched_alert = None

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        agent_name = alert.get("agent", {}).get("name")
        syscheck = alert.get("syscheck", {})
        path = syscheck.get("path")
        event = syscheck.get("event")
        groups = alert.get("rule", {}).get("groups", [])
        timestamp = alert.get("timestamp", "")

        alert_time = parse_wazuh_timestamp(timestamp)
        age = now - alert_time

        if agent_name != TARGET_AGENT_NAME:
            continue

        if path != AUTHORIZED_KEYS_PATH:
            continue

        if event != "modified":
            continue

        if "syscheck" not in groups:
            continue

        if age > RECENT_WINDOW_SECONDS:
            print(f"[INFO] Ignoring old authorized_keys alert. Age: {int(age)} seconds")
            continue

        matched_alert = alert
        break

    if not matched_alert:
        print("[RESULT] No recent Wazuh authorized_keys modification alert found.")
        return 1

    print("[DETECTED] Recent Wazuh alert found for authorized_keys modification.")
    print("[RULE]", matched_alert.get("rule", {}).get("id"), "-", matched_alert.get("rule", {}).get("description"))

    if old_key_is_active():
        print("[CONFIRMED] Old compromised SSH key is currently active in authorized_keys.")
        return 0

    print("[RESULT] Wazuh alert found, but old compromised key is not active now.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
