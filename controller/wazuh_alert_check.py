import json
import subprocess
import sys

# Support running this file either as part of the controller package or directly.
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


# Exact cron artefact created by the controlled attack.
ATTACK_PATH = "/etc/cron.d/realtime_evil_persistence"
# Only alerts from the intended experiment target are accepted.
TARGET_AGENT_NAME = "thesis-self-healing-vm"
# Scenario name used when tracking whether an alert has already been handled.
SCENARIO = "malicious_cron_persistence"


def run_command(command):
    # Execute a local subprocess and return its exit code and captured output.
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
    # Perform a live check on the target VM rather than trusting historical Wazuh data alone.
    # Explicit EXISTS/MISSING markers avoid treating empty output as proof of absence.
    result = run_target_command(
        f"if test -f {ATTACK_PATH}; "
        "then echo EXISTS; else echo MISSING; fi"
    )

    return "EXISTS" in result["stdout"]


def unprocessed_wazuh_alert_exists():
    # Search the Wazuh Manager's JSON alert log for entries containing the exact cron path.
    # tail limits parsing to the most recent candidate lines.
    remote_command = (
        "sudo grep -F "
        f"'{ATTACK_PATH}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 100 || true"
    )

    result = run_wazuh_command(remote_command)

    # No returned alert text means there is no candidate cron alert to evaluate.
    if not result["stdout"]:
        print("[NO WAZUH CRON ALERT FOUND]")
        return False

    matching_alerts = []

    # Wazuh stores one JSON alert per line, so parse each candidate independently.
    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            # Ignore malformed/non-JSON lines instead of allowing them to authorise recovery.
            continue

        # Extract only the fields needed for the exact alert-selection decision.
        alert_id = str(alert.get("id", ""))
        agent_name = alert.get("agent", {}).get("name")
        syscheck = alert.get("syscheck", {})
        path = syscheck.get("path")
        event = syscheck.get("event")
        groups = alert.get("rule", {}).get("groups", [])

        # This is Listing 2 from the report.
        # A rule ID by itself is not enough: the controller requires the expected target,
        # exact attack path, a file-added/modified FIM event, and syscheck classification.
        if (
            alert_id
            and agent_name == TARGET_AGENT_NAME
            and path == ATTACK_PATH
            and event in {"added", "modified"}
            and "syscheck" in groups
        ):
            matching_alerts.append(alert)

    # Candidate alerts existed, but none satisfied every required selection condition.
    if not matching_alerts:
        print("[NO MATCHING WAZUH CRON ALERT FOUND]")
        return False

    # Use the latest exact matching alert from the collected candidates.
    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    # Prevent an alert whose recovery already completed from triggering another replacement.
    if is_alert_processed(SCENARIO, alert_id):
        print(
            f"[ALREADY PROCESSED] Cron alert ID {alert_id} "
            "has already completed recovery."
        )
        return False

    # Persist the exact selected alert so later workflow stages refer to the same incident.
    save_selected_alert(SCENARIO, alert_id)

    print("[UNPROCESSED WAZUH CRON ALERT FOUND]")
    print(f"[ALERT ID] {alert_id}")
    print(json.dumps(latest_alert))
    return True


def recoverable_alert_exists():
    # Start gate, part 1: require an exact, unprocessed Wazuh alert.
    if not unprocessed_wazuh_alert_exists():
        return False

    print("[2] Confirming persistence still exists on target VM...")

    # Start gate, part 2: require the malicious cron file to still exist right now.
    # This prevents a stale historical alert from authorising destructive recovery.
    if target_persistence_exists():
        print("[CONFIRMED] Persistence is still present on target VM.")
        return True

    print(
        "[NO ACTION] An unprocessed alert exists, "
        "but cron persistence is absent."
    )
    return False


def run_recovery_controller():
    # Launch the scenario's full recovery orchestrator only after both start-gate checks pass.
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

    # Exit code 0 means the called recovery workflow completed successfully.
    return code == 0


def main():
    # --check-only lets the orchestrator perform detection/confirmation without recursively
    # launching the recovery controller from this helper script.
    check_only = "--check-only" in sys.argv

    print(
        "[1] Checking Wazuh for an unprocessed "
        "cron-persistence alert..."
    )

    # Do not proceed unless both a suitable alert and live compromise are present.
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
