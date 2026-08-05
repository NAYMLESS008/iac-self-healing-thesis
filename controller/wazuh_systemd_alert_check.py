import json
import subprocess
import sys
import time
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
    remote_command = (
        f"if test -f {SERVICE_PATH}; "
        "then echo SERVICE_FILE_PRESENT; "
        "else echo SERVICE_FILE_ABSENT; fi; "
        f"if test -f {SCRIPT_PATH}; "
        "then echo SCRIPT_FILE_PRESENT; "
        "else echo SCRIPT_FILE_ABSENT; fi; "
        "if sudo systemctl is-active --quiet "
        "thesis-persistence.service; "
        "then echo SERVICE_ACTIVE; "
        "else echo SERVICE_INACTIVE; fi"
    )

    required_markers = {
        "SERVICE_FILE_PRESENT",
        "SCRIPT_FILE_PRESENT",
        "SERVICE_ACTIVE",
    }

    for attempt in range(1, 4):
        result = run_target_command(remote_command)
        output = result["stdout"].strip()

        print(
            f"[TARGET STATE] attempt {attempt}/3: "
            f"{output or 'EMPTY'}"
        )

        output_markers = set(output.splitlines())

        if required_markers.issubset(output_markers):
            return True

        if output:
            return False

        if result["stderr"]:
            print("[TARGET CHECK STDERR]")
            print(result["stderr"])

        if attempt < 3:
            time.sleep(5)

    return False

def unprocessed_wazuh_alert_exists():
    remote_command = (
        "sudo grep -F "
        f"'{SERVICE_PATH}' "
        "/var/ossec/logs/alerts/alerts.json "
        "2>/dev/null || true; "
        "sudo find /var/ossec/logs/alerts "
        "-type f -name 'ossec-alerts-*.json.gz' "
        "-exec zgrep -h -F "
        f"'{SERVICE_PATH}' "
        "{} + 2>/dev/null || true"
    )

    result = run_wazuh_command(remote_command)

    if not result["stdout"]:
        print("[NO WAZUH SYSTEMD ALERT FOUND]")
        return False

    matching_alerts = {}

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
            matching_alerts[alert_id] = alert

    if not matching_alerts:
        print(
            "[NO MATCHING WAZUH SYSTEMD "
            "FIM ALERT FOUND]"
        )
        return False

    ordered_alerts = sorted(
        matching_alerts.values(),
        key=lambda alert: alert.get("timestamp", ""),
        reverse=True,
    )

    selected_alert = None

    for alert in ordered_alerts:
        alert_id = str(alert["id"])

        if not is_alert_processed(
            SCENARIO,
            alert_id,
        ):
            selected_alert = alert
            break

    if selected_alert is None:
        print(
            "[NO UNPROCESSED WAZUH SYSTEMD "
            "ALERT FOUND]"
        )
        return False

    alert_id = str(selected_alert["id"])

    save_selected_alert(
        SCENARIO,
        alert_id,
    )

    print(
        "[UNPROCESSED WAZUH SYSTEMD "
        "ALERT FOUND]"
    )
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(selected_alert))

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
