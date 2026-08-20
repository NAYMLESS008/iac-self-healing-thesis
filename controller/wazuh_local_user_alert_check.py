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


TARGET_AGENT_NAME = "thesis-self-healing-vm"
BACKDOOR_USER = "thesisbackdoor"
CREATE_USER_RULE_ID = "5902"
SCENARIO = "unauthorized_local_user"


def target_user_exists():
    result = run_target_command(
        f"if id {BACKDOOR_USER} >/dev/null 2>&1; "
        "then echo EXISTS; else echo MISSING; fi"
    )

    return "EXISTS" in result["stdout"]


def target_user_is_privileged():
    result = run_target_command(
        f"id -nG {BACKDOOR_USER} 2>/dev/null || true"
    )

    return "sudo" in result["stdout"].split()


def unprocessed_user_alert_exists():
    remote_command = (
        "sudo grep -F "
        f"'{BACKDOOR_USER}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(remote_command)

    if not result["stdout"]:
        print("[NO WAZUH USER-CREATION ALERT FOUND]")
        return False

    matching_alerts = []

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert_id = str(alert.get("id", ""))
        agent_name = alert.get("agent", {}).get("name")
        rule_id = str(alert.get("rule", {}).get("id", ""))
        created_user = alert.get("data", {}).get("dstuser")

        if (
            alert_id
            and agent_name == TARGET_AGENT_NAME
            and rule_id == CREATE_USER_RULE_ID
            and created_user == BACKDOOR_USER
        ):
            matching_alerts.append(alert)

    if not matching_alerts:
        print("[NO MATCHING USER-CREATION ALERT FOUND]")
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(SCENARIO, alert_id):
        print(
            f"[ALREADY PROCESSED] User alert ID {alert_id} "
            "has already completed recovery."
        )
        return False

    save_selected_alert(SCENARIO, alert_id)

    print("[UNPROCESSED USER-CREATION ALERT FOUND]")
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(latest_alert))
    return True


def recoverable_user_persistence_exists():
    if not unprocessed_user_alert_exists():
        return False

    print("[2] Confirming unauthorized account still exists...")

    if not target_user_exists():
        print(
            "[NO ACTION] User-creation alert found, "
            "but the account is absent."
        )
        return False

    print("[CONFIRMED] Unauthorized account still exists.")

    if not target_user_is_privileged():
        print(
            "[NO ACTION] Account exists but does not have "
            "sudo membership."
        )
        return False

    print("[CONFIRMED] Unauthorized account has sudo membership.")
    return True


def main():
    print(
        "[1] Checking Wazuh for an unprocessed unauthorized "
        "local-user alert..."
    )

    if not recoverable_user_persistence_exists():
        print(
            "[STOP] No active unprocessed unauthorized-user "
            "persistence requires recovery."
        )
        return 1

    print(
        "[CHECK ONLY] Active privileged unauthorized account "
        "confirmed."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
