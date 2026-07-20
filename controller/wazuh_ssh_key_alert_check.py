import json
import subprocess
import sys

from controller.alert_state import (
    is_alert_processed,
    save_selected_alert,
)
from controller.iap_helpers import run_wazuh_command


TARGET_AGENT_NAME = "thesis-self-healing-vm"
AUTHORIZED_KEYS_PATH = "/home/thesisadmin/.ssh/authorized_keys"
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"
SCENARIO = "ssh_key_persistence"


def old_key_is_active():
    result = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "thesis-target-old-compromised-key",
            "whoami && hostname",
        ],
        capture_output=True,
        text=True,
    )

    return (
        result.returncode == 0
        and "thesisadmin" in result.stdout
    )


def unprocessed_ssh_alert_exists():
    command = (
        "sudo grep -F "
        f"'{AUTHORIZED_KEYS_PATH}' "
        f"{ALERTS_FILE} "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(command)

    if not result["success"]:
        print("[ERROR] Could not read Wazuh alerts.")
        print(result["stderr"])
        return False

    matching_alerts = []

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert_id = str(alert.get("id", ""))
        agent_name = alert.get("agent", {}).get("name")
        syscheck = alert.get("syscheck", {})
        path = syscheck.get("path")
        event = syscheck.get("event")
        groups = alert.get("rule", {}).get("groups", [])

        if (
            alert_id
            and agent_name == TARGET_AGENT_NAME
            and path == AUTHORIZED_KEYS_PATH
            and event in {"added", "modified"}
            and "syscheck" in groups
        ):
            matching_alerts.append(alert)

    if not matching_alerts:
        print(
            "[RESULT] No matching Wazuh authorized_keys "
            "alert found."
        )
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(SCENARIO, alert_id):
        print(
            f"[ALREADY PROCESSED] SSH alert ID {alert_id} "
            "has already completed recovery."
        )
        return False

    save_selected_alert(SCENARIO, alert_id)

    print("[UNPROCESSED SSH-KEY ALERT FOUND]")
    print(f"[ALERT ID] {alert_id}")
    print(
        "[RULE]",
        latest_alert.get("rule", {}).get("id"),
        "-",
        latest_alert.get("rule", {}).get("description"),
    )
    print(json.dumps(latest_alert))
    return True


def main():
    print(
        "[INFO] Checking Wazuh for an unprocessed "
        "authorized_keys alert..."
    )

    if not unprocessed_ssh_alert_exists():
        return 1

    if old_key_is_active():
        print(
            "[CONFIRMED] Old compromised SSH key is "
            "currently active."
        )
        return 0

    print(
        "[RESULT] An unprocessed alert exists, but the old "
        "compromised key is not active."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
