import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from controller.alert_state import mark_selected_alert_processed


RESULTS_FILE = Path(
    "results/local_user_recovery_orchestrator_results.csv"
)

SCENARIO = "unauthorized_local_user"

FIELDNAMES = [
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


def run_step(description, module_name):
    print(f"\n[STEP] {description}")

    start = time.perf_counter()

    result = subprocess.run(
        [sys.executable, "-m", module_name],
        text=True
    )

    duration = round(time.perf_counter() - start, 2)

    if result.returncode == 0:
        print(
            f"\n[OK] {description} completed in "
            f"{duration} seconds."
        )
        return True, duration

    print(
        f"\n[FAIL] {description} failed in "
        f"{duration} seconds."
    )
    return False, duration


def create_result_row():
    return {
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),
        "scenario": SCENARIO,
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
        "final_result": "NOT_COMPLETED",
    }


def write_result(row):
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    file_exists = RESULTS_FILE.exists()

    with RESULTS_FILE.open(
        "a",
        newline="",
        encoding="utf-8"
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=FIELDNAMES
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


def stop_and_log(result_name, row, workflow_start):
    total_duration = round(
        time.perf_counter() - workflow_start,
        2
    )

    row["total_duration_seconds"] = total_duration
    row["final_result"] = result_name

    write_result(row)

    print(f"\n[STOP] {result_name}")
    print(
        f"[METRIC] total_duration_seconds = "
        f"{total_duration}"
    )

    return 1


def main():
    print("====================================================")
    print(" Starting unauthorized local-user recovery workflow ")
    print("====================================================")

    workflow_start = time.perf_counter()
    row = create_result_row()

    success, duration = run_step(
        "Wazuh detection and active-user confirmation",
        "controller.wazuh_local_user_alert_check"
    )

    row["wazuh_detection"] = "PASS" if success else "FAIL"
    row["detection_check_duration_seconds"] = duration

    if not success:
        return stop_and_log(
            "NO_RECOVERY_TRIGGERED",
            row,
            workflow_start
        )

    success, duration = run_step(
        "Evidence capture before replacement",
        "controller.capture_local_user_evidence"
    )

    row["evidence_capture"] = "PASS" if success else "FAIL"
    row["evidence_capture_duration_seconds"] = duration

    if not success:
        return stop_and_log(
            "FAILED_EVIDENCE_CAPTURE",
            row,
            workflow_start
        )

    success, duration = run_step(
        "Quarantine compromised target VM",
        "controller.quarantine_target"
    )

    row["quarantine"] = "PASS" if success else "FAIL"
    row["quarantine_duration_seconds"] = duration

    if not success:
        return stop_and_log(
            "FAILED_QUARANTINE",
            row,
            workflow_start
        )

    success, duration = run_step(
        "Remove stale Wazuh agent registration",
        "controller.remove_stale_wazuh_agent"
    )

    row["stale_agent_cleanup"] = (
        "PASS" if success else "FAIL"
    )
    row["stale_agent_cleanup_duration_seconds"] = duration

    if not success:
        return stop_and_log(
            "FAILED_STALE_AGENT_CLEANUP",
            row,
            workflow_start
        )

    success, duration = run_step(
        "Terraform replacement recovery",
        "controller.recover_replace"
    )

    row["replacement_recovery"] = (
        "PASS" if success else "FAIL"
    )
    row["replacement_duration_seconds"] = duration

    if not success:
        return stop_and_log(
            "FAILED_REPLACEMENT_RECOVERY",
            row,
            workflow_start
        )

    success, duration = run_step(
        "Post-recovery local-user and monitoring validation",
        "controller.validate_local_user_recovery"
    )

    row["post_recovery_validation"] = (
        "PASS" if success else "FAIL"
    )
    row["validation_duration_seconds"] = duration

    if not success:
        row["monitoring_restored"] = "FAIL"

        return stop_and_log(
            "FAILED_POST_RECOVERY_VALIDATION",
            row,
            workflow_start
        )

    row["monitoring_restored"] = "PASS"
    row["residual_compromise_count"] = "0/3"
    row["residual_compromise_score"] = "0"

    if not mark_selected_alert_processed(SCENARIO):
        return stop_and_log(
            "FAILED_ALERT_STATE_UPDATE",
            row,
            workflow_start
        )

    total_duration = round(
        time.perf_counter() - workflow_start,
        2
    )

    row["total_duration_seconds"] = total_duration
    row["final_result"] = "PASS"

    write_result(row)

    print(
        "\n[SUCCESS] Full unauthorized local-user "
        "recovery workflow passed."
    )
    print("[METRIC] residual_compromise_count = 0/3")
    print("[METRIC] residual_compromise_score = 0")
    print("[METRIC] monitoring_restored = PASS")
    print(
        f"[METRIC] total_duration_seconds = "
        f"{total_duration}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
