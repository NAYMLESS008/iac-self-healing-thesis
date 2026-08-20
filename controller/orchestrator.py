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
CAPTURE_EVIDENCE = CONTROLLER_DIR / "capture_cron_evidence.py"
RECOVER_REPLACE = CONTROLLER_DIR / "recover_replace.py"


def run_script(script_path, args=None):
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
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    file_exists = RESULTS_FILE.exists()

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=row.keys())

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


def main():
    print("================================================")
    print(" Starting IaC Replacement Recovery Orchestrator ")
    print("================================================")

    workflow_start = time.time()
    timestamp = datetime.now(timezone.utc).isoformat()

    attack_type = "cron_persistence"
    detection_status = "unknown"
    evidence_status = "not_captured"
    recovery_strategy = "terraform_replacement"
    recovery_success = False
    validation_success = False
    error_message = ""

    detection_duration = 0
    evidence_duration = 0
    recovery_duration = 0

    # Step 1: Check Wazuh alert and confirm active persistence.
    alert_code, detection_duration = run_script(WAZUH_ALERT_CHECK, ["--check-only"])

    if alert_code == 0:
        detection_status = "detected_active"
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
            "evidence_status": evidence_status,
            "evidence_duration_seconds": evidence_duration,
            "recovery_strategy": "none",
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
            "evidence_status": evidence_status,
            "evidence_duration_seconds": evidence_duration,
            "recovery_strategy": "none",
            "recovery_duration_seconds": recovery_duration,
            "recovery_success": recovery_success,
            "validation_success": validation_success,
            "total_workflow_duration_seconds": total_duration,
            "error_message": error_message
        })

        return 2

    # Step 2: Capture evidence before destructive replacement.
    evidence_code, evidence_duration = run_script(CAPTURE_EVIDENCE)

    if evidence_code == 0:
        evidence_status = "captured"
        print("[OK] Pre-replacement evidence captured.")
    else:
        evidence_status = "capture_failed"
        error_message = "Evidence capture failed. Replacement stopped to avoid destroying evidence."
        print("[ERROR] Evidence capture failed. Stopping before Terraform replacement.")

        total_duration = round(time.time() - workflow_start, 2)

        log_result({
            "timestamp_utc": timestamp,
            "attack_type": attack_type,
            "detection_status": detection_status,
            "detection_duration_seconds": detection_duration,
            "evidence_status": evidence_status,
            "evidence_duration_seconds": evidence_duration,
            "recovery_strategy": "none",
            "recovery_duration_seconds": recovery_duration,
            "recovery_success": recovery_success,
            "validation_success": validation_success,
            "total_workflow_duration_seconds": total_duration,
            "error_message": error_message
        })

        return 3

    # Step 3: Terraform-driven replacement recovery.
    replace_code, recovery_duration = run_script(RECOVER_REPLACE)

    if replace_code == 0:
        recovery_success = True
        validation_success = True
        print("[OK] Terraform replacement recovery completed and validated.")
    else:
        recovery_success = False
        validation_success = False
        error_message = "Terraform replacement recovery failed validation."
        print("[ERROR] Terraform replacement recovery failed.")

    total_duration = round(time.time() - workflow_start, 2)

    log_result({
        "timestamp_utc": timestamp,
        "attack_type": attack_type,
        "detection_status": detection_status,
        "detection_duration_seconds": detection_duration,
        "evidence_status": evidence_status,
        "evidence_duration_seconds": evidence_duration,
        "recovery_strategy": recovery_strategy,
        "recovery_duration_seconds": recovery_duration,
        "recovery_success": recovery_success,
        "validation_success": validation_success,
        "total_workflow_duration_seconds": total_duration,
        "error_message": error_message
    })

    print("\n================================================")
    print(" Replacement recovery orchestrator completed ")
    print("================================================")
    print(f"Result logged to: {RESULTS_FILE}")

    if recovery_success and validation_success:
        return 0

    return 4


if __name__ == "__main__":
    raise SystemExit(main())
