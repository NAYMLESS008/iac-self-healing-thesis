import json
import subprocess
import sys

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


ATTACK_PATH = "/etc/cron.d/realtime_evil_persistence"
TARGET_AGENT_NAME = "thesis-self-healing-vm"
SCENARIO = "malicious_cron_persistence"


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return (
        result.returncode,
        result.stdout.strip(),
        result.stderr.strip()
    )


def target_persistence_exists():
    result = run_target_command(
        f"if test -f {ATTACK_PATH}; "
        "then echo EXISTS; else echo MISSING; fi"
    )

    return "EXISTS" in result["stdout"]


def unprocessed_wazuh_alert_exists():
    remote_command = (
        "sudo grep -F "
        f"'{ATTACK_PATH}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(remote_command)

    if not result["stdout"]:
        print("[NO WAZUH CRON ALERT FOUND]")
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
            and path == ATTACK_PATH
            and event in {"added", "modified"}
            and "syscheck" in groups
        ):
            matching_alerts.append(alert)

    if not matching_alerts:
        print("[NO MATCHING WAZUH CRON ALERT FOUND]")
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(SCENARIO, alert_id):
        print(
            f"[ALREADY PROCESSED] Cron alert ID {alert_id} "
            "has already completed recovery."
        )
        return False

    save_selected_alert(SCENARIO, alert_id)

    print("[UNPROCESSED WAZUH CRON ALERT FOUND]")
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(latest_alert))
    return True


def recoverable_alert_exists():
    if not unprocessed_wazuh_alert_exists():
        return False

    print("[2] Confirming persistence still exists on target VM...")

    if target_persistence_exists():
        print("[CONFIRMED] Persistence is still present on target VM.")
        return True

    print(
        "[NO ACTION] An unprocessed alert exists, "
        "but cron persistence is absent."
    )
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
    check_only = "--check-only" in sys.argv

    print(
        "[1] Checking Wazuh for an unprocessed "
        "cron-persistence alert..."
    )

    if not recoverable_alert_exists():
        print(
            "[STOP] No active unprocessed cron persistence "
            "requires recovery."
        )
        return 1

    if check_only:
        print(
            "[CHECK ONLY] Active recoverable cron persistence "
            "confirmed."
        )
        return 0

    print(
        "[3] Unprocessed alert and active persistence confirmed. "
        "Triggering recovery..."
    )

    if run_recovery_controller():
        print("[DONE] Alert-driven recovery workflow completed.")
        return 0

    print("[ERROR] Recovery controller failed.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
