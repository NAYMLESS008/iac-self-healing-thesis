import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONTROLLER_DIR = PROJECT_ROOT / "controller"
RESULTS_FILE = PROJECT_ROOT / "results" / "orchestrator_results.csv"

WAZUH_ALERT_CHECK = CONTROLLER_DIR / "wazuh_alert_check.py"
CRON_SELF_HEAL = CONTROLLER_DIR / "cron_self_heal.py"
RECOVER_REPLACE = CONTROLLER_DIR / "recover_replace.py"


def run_script(script_path, args=None):
    """
    Runs another controller script and measures how long it takes.
    """
    if args is None:
        args = []

    print(f"\n[RUNNING] {script_path.name} {' '.join(args)}")

    start_time = time.time()

    result = subprocess.run(
        [sys.executable, str(script_path), *args],
        text=True
    )

    duration = round(time.time() - start_time, 2)

    return result.returncode, duration


def log_result(row):
    """
    Logs one orchestrator-level experiment result.
    """
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    file_exists = RESULTS_FILE.exists()

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=row.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


def main():
    print("====================================")
    print(" Starting IaC Recovery Orchestrator ")
    print("====================================")

    workflow_start = time.time()
    timestamp = datetime.now(timezone.utc).isoformat()

    attack_type = "cron_persistence"
    detection_status = "unknown"
    recovery_strategy = "none"
    recovery_success = False
    validation_success = False
    error_message = ""
    recovery_duration = 0

    # Step 1: Check only. Do not let wazuh_alert_check.py trigger recovery itself.
    alert_code, detection_duration = run_script(WAZUH_ALERT_CHECK, ["--check-only"])

    if alert_code == 0:
        detection_status = "detected"
        print("[OK] Fresh Wazuh alert and active persistence confirmed.")

    elif alert_code == 1:
        detection_status = "not_detected"
        error_message = "No active recoverable cron persistence found."
        print("[INFO] No active recoverable cron persistence found. No recovery triggered.")

        total_duration = round(time.time() - workflow_start, 2)

        log_result({
            "timestamp_utc": timestamp,
            "attack_type": attack_type,
            "detection_status": detection_status,
            "detection_duration_seconds": detection_duration,
            "recovery_strategy": recovery_strategy,
            "recovery_duration_seconds": recovery_duration,
            "recovery_success": recovery_success,
            "validation_success": validation_success,
            "total_workflow_duration_seconds": total_duration,
            "error_message": error_message
        })

        return 1

    else:
        detection_status = "error"
        error_message = "Wazuh alert check failed."
        print("[ERROR] Wazuh alert check failed.")

        total_duration = round(time.time() - workflow_start, 2)

        log_result({
            "timestamp_utc": timestamp,
            "attack_type": attack_type,
            "detection_status": detection_status,
            "detection_duration_seconds": detection_duration,
            "recovery_strategy": recovery_strategy,
            "recovery_duration_seconds": recovery_duration,
            "recovery_success": recovery_success,
            "validation_success": validation_success,
            "total_workflow_duration_seconds": total_duration,
            "error_message": error_message
        })

        return 2

    # Step 2: Try in-place repair first.
    repair_code, repair_duration = run_script(CRON_SELF_HEAL)

    if repair_code == 0:
        recovery_strategy = "in_place_repair"
        recovery_duration = repair_duration
        recovery_success = True
        validation_success = True
        print("[OK] In-place cron recovery completed successfully.")

    else:
        print("[WARN] In-place repair failed. Starting Terraform replacement fallback.")

        replace_code, replace_duration = run_script(RECOVER_REPLACE)

        recovery_strategy = "terraform_replacement"
        recovery_duration = round(repair_duration + replace_duration, 2)

        if replace_code == 0:
            recovery_success = True
            validation_success = True
            print("[OK] Terraform replacement completed successfully.")
        else:
            recovery_success = False
            validation_success = False
            error_message = "Both in-place repair and Terraform replacement failed."
            print("[ERROR] Recovery failed.")

    total_duration = round(time.time() - workflow_start, 2)

    log_result({
        "timestamp_utc": timestamp,
        "attack_type": attack_type,
        "detection_status": detection_status,
        "detection_duration_seconds": detection_duration,
        "recovery_strategy": recovery_strategy,
        "recovery_duration_seconds": recovery_duration,
        "recovery_success": recovery_success,
        "validation_success": validation_success,
        "total_workflow_duration_seconds": total_duration,
        "error_message": error_message
    })

    print("\n====================================")
    print(" Orchestrator workflow completed ")
    print("====================================")
    print(f"Result logged to: {RESULTS_FILE}")

    if recovery_success and validation_success:
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
