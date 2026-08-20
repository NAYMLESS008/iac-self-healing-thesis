import json
import sys

from controller.alert_state import (
    is_alert_processed,
    save_selected_alert,
)
from controller.iap_helpers import (
    run_target_command,
    run_wazuh_command,
)


AUTHORIZED_KEYS = "/home/thesisadmin/.ssh/authorized_keys"
ATTACK_MARKER = "THESIS_UNAUTHORIZED_SSH_KEY"
TARGET_AGENT_NAME = "thesis-self-healing-vm"
SCENARIO = "unauthorized_ssh_public_key"


def target_persistence_exists():
    for attempt in range(1, 4):
        result = run_target_command(
            f"if sudo grep -Fq '{ATTACK_MARKER}' {AUTHORIZED_KEYS}; "
            "then echo PRESENT; else echo ABSENT; fi"
        )

        stdout = result["stdout"]

        if "PRESENT" in stdout:
            return True

        if "ABSENT" in stdout:
            return False

        print(
            f"[WARN] Incomplete SSH-key state output "
            f"on attempt {attempt}/3; retrying..."
        )

        if attempt < 3:
            import time
            time.sleep(5)

    print("[ERROR] Could not determine SSH-key persistence state.")
    return False


def unprocessed_wazuh_alert_exists():
    command = (
        "sudo grep -F "
        f"'{AUTHORIZED_KEYS}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(command)

    if not result["stdout"]:
        print("[NO WAZUH SSH PUBLIC-KEY ALERT FOUND]")
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
            and path == AUTHORIZED_KEYS
            and event in {"added", "modified"}
            and "syscheck" in groups
        ):
            matching_alerts.append(alert)

    if not matching_alerts:
        print("[NO MATCHING WAZUH SSH PUBLIC-KEY ALERT FOUND]")
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(SCENARIO, alert_id):
        print(
            f"[ALREADY PROCESSED] SSH public-key alert "
            f"{alert_id} has already completed recovery."
        )
        return False

    save_selected_alert(SCENARIO, alert_id)

    print("[UNPROCESSED WAZUH SSH PUBLIC-KEY ALERT FOUND]")
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(latest_alert))

    return True


def recoverable_alert_exists():
    if not unprocessed_wazuh_alert_exists():
        return False

    print(
        "[2] Confirming unauthorized SSH public key "
        "still exists on target VM..."
    )

    if target_persistence_exists():
        print(
            "[CONFIRMED] Unauthorized SSH public key "
            "is still present."
        )
        return True

    print(
        "[NO ACTION] An unprocessed alert exists, but the "
        "unauthorized SSH public key is absent."
    )
    return False


def main():
    print(
        "[1] Checking Wazuh for an unprocessed "
        "SSH public-key persistence alert..."
    )

    if not recoverable_alert_exists():
        print(
            "[STOP] No active unauthorized SSH public-key "
            "persistence requires recovery."
        )
        return 1

    print(
        "[CHECK ONLY] Active recoverable unauthorized "
        "SSH public-key persistence confirmed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
