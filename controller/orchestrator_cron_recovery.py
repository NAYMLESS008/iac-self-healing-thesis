from controller.alert_state import mark_selected_alert_processed
import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


RESULTS_DIR = Path("results")
RESULTS_FILE = RESULTS_DIR / "cron_recovery_orchestrator_results.csv"


def run_step(name, command):
    print(f"\n[STEP] {name}")
    start_time = time.time()

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    duration = round(time.time() - start_time, 2)

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("[STDERR]")
        print(result.stderr)

    if result.returncode == 0:
        print(f"[OK] {name} completed in {duration} seconds.")
    else:
        print(f"[FAIL] {name} failed in {duration} seconds.")

    return {
        "success": result.returncode == 0,
        "return_code": result.returncode,
        "duration": duration,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def log_result(row):
    RESULTS_DIR.mkdir(exist_ok=True)
    file_exists = RESULTS_FILE.exists()

    fieldnames = [
        "timestamp_utc",
        "scenario",
        "wazuh_detection",
        "detection_check_duration_seconds",
        "evidence_capture",
        "evidence_capture_duration_seconds",
        "quarantine",
        "quarantine_duration_seconds",
        "stale_agent_cleanup",
        "stale_agent_cleanup_duration_seconds",
        "replacement_recovery",
        "replacement_duration_seconds",
        "post_recovery_validation",
        "validation_duration_seconds",
        "monitoring_restored",
        "residual_compromise_count",
        "residual_compromise_score",
        "total_duration_seconds",
        "final_result",
    ]

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


def stop_and_log(reason, row, workflow_start):
    row["total_duration_seconds"] = round(
        time.time() - workflow_start,
        2
    )
    row["final_result"] = reason

    log_result(row)

    print(f"\n[STOP] {reason}")
    print(
        f"[METRIC] total_duration_seconds = "
        f"{row['total_duration_seconds']}"
    )

    return 1


def main():
    print("================================================")
    print(" Starting malicious cron recovery orchestrator ")
    print("================================================")

    workflow_start = time.time()

    row = {
        "timestamp_utc": datetime.now(timezone.utc).isoformat(
            timespec="seconds"
        ),
        "scenario": "malicious_cron_persistence",
        "wazuh_detection": "NOT_RUN",
        "detection_check_duration_seconds": "",
        "evidence_capture": "NOT_RUN",
        "evidence_capture_duration_seconds": "",
        "quarantine": "NOT_RUN",
        "quarantine_duration_seconds": "",
        "stale_agent_cleanup": "NOT_RUN",
        "stale_agent_cleanup_duration_seconds": "",
        "replacement_recovery": "NOT_RUN",
        "replacement_duration_seconds": "",
        "post_recovery_validation": "NOT_RUN",
        "validation_duration_seconds": "",
        "monitoring_restored": "NOT_RUN",
        "residual_compromise_count": "UNKNOWN",
        "residual_compromise_score": "UNKNOWN",
        "total_duration_seconds": "",
        "final_result": "",
    }

    detection = run_step(
        "Wazuh detection and active cron confirmation",
        [
            sys.executable,
            "controller/wazuh_alert_check.py",
            "--check-only",
        ]
    )

    row["wazuh_detection"] = (
        "PASS" if detection["success"] else "FAIL"
    )
    row["detection_check_duration_seconds"] = detection["duration"]

    if not detection["success"]:
        return stop_and_log(
            "NO_RECOVERY_TRIGGERED",
            row,
            workflow_start
        )

    evidence = run_step(
        "Evidence capture before replacement",
        [
            sys.executable,
            "-m",
            "controller.capture_cron_evidence",
        ]
    )

    row["evidence_capture"] = (
        "PASS" if evidence["success"] else "FAIL"
    )
    row["evidence_capture_duration_seconds"] = evidence["duration"]

    if not evidence["success"]:
        return stop_and_log(
            "FAILED_EVIDENCE_CAPTURE",
            row,
            workflow_start
        )

    quarantine = run_step(
        "Quarantine compromised target VM",
        [
            sys.executable,
            "-m",
            "controller.quarantine_target",
        ]
    )

    row["quarantine"] = (
        "PASS" if quarantine["success"] else "FAIL"
    )
    row["quarantine_duration_seconds"] = quarantine["duration"]

    if not quarantine["success"]:
        return stop_and_log(
            "FAILED_QUARANTINE",
            row,
            workflow_start
        )

    cleanup = run_step(
        "Remove stale Wazuh agent registration",
        [
            sys.executable,
            "-m",
            "controller.remove_stale_wazuh_agent",
        ]
    )

    row["stale_agent_cleanup"] = (
        "PASS" if cleanup["success"] else "FAIL"
    )
    row["stale_agent_cleanup_duration_seconds"] = cleanup["duration"]

    if not cleanup["success"]:
        return stop_and_log(
            "FAILED_STALE_AGENT_CLEANUP",
            row,
            workflow_start
        )

    replacement = run_step(
        "Terraform replacement recovery",
        [
            sys.executable,
            "-m",
            "controller.recover_replace",
        ]
    )

    row["replacement_recovery"] = (
        "PASS" if replacement["success"] else "FAIL"
    )
    row["replacement_duration_seconds"] = replacement["duration"]

    if not replacement["success"]:
        return stop_and_log(
            "FAILED_REPLACEMENT_RECOVERY",
            row,
            workflow_start
        )

    validation = run_step(
        "Post-recovery cron and monitoring validation",
        [
            sys.executable,
            "-m",
            "controller.validate_cron_recovery",
        ]
    )

    row["post_recovery_validation"] = (
        "PASS" if validation["success"] else "FAIL"
    )
    row["validation_duration_seconds"] = validation["duration"]

    if validation["success"]:
        row["monitoring_restored"] = "PASS"
        row["residual_compromise_count"] = "0/2"
        row["residual_compromise_score"] = 0
    else:
        row["monitoring_restored"] = "FAIL"
        row["residual_compromise_count"] = "UNKNOWN"
        row["residual_compromise_score"] = "UNKNOWN"

    row["total_duration_seconds"] = round(
        time.time() - workflow_start,
        2
    )

    row["final_result"] = (
        "PASS" if validation["success"] else "FAIL"
    )

    log_result(row)

    if validation["success"]:
        print("\n[SUCCESS] Full malicious cron recovery workflow passed.")
        print("[METRIC] residual_compromise_count = 0/2")
        print("[METRIC] residual_compromise_score = 0")
        print("[METRIC] monitoring_restored = PASS")
        print(
            f"[METRIC] total_duration_seconds = "
            f"{row['total_duration_seconds']}"
        )
        return 0

    print("\n[FAIL] Post-recovery validation failed.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())

