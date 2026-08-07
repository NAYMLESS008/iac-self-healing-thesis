import csv
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

from controller.alert_state import mark_selected_alert_processed


SCENARIO = "unauthorized_local_user"

RESULTS_FILE = Path(
    "results/local_user_recovery_formal_results.csv"
)

FIELDNAMES = [
    "timestamp_utc",
    "scenario",
    "wazuh_detection",
    "detection_check_duration_seconds",
    "evidence_capture",
    "evidence_capture_duration_seconds",
    "evidence_items_required",
    "evidence_items_captured",
    "evidence_completeness_percentage",
    "quarantine",
    "quarantine_duration_seconds",
    "stale_agent_cleanup",
    "stale_agent_cleanup_duration_seconds",
    "replacement_recovery",
    "replacement_duration_seconds",
    "post_recovery_validation",
    "validation_duration_seconds",
    "validation_indicators_total",
    "validation_indicators_passed",
    "validation_success_percentage",
    "monitoring_restored",
    "fim_realtime_ready",
    "monitoring_restoration_duration_seconds",
    "residual_compromise_count",
    "residual_compromise_score",
    "total_duration_seconds",
    "final_result",
]


def run_module(module_name):
    start = time.perf_counter()

    result = subprocess.run(
        [sys.executable, "-m", module_name],
        capture_output=True,
        text=True,
    )

    duration = round(
        time.perf_counter() - start,
        2,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("[STDERR]")
        print(result.stderr)

    return {
        "success": result.returncode == 0,
        "duration": duration,
        "output": result.stdout,
    }


def get_metric(output, name):
    prefix = f"[METRIC] {name} = "

    for line in output.splitlines():
        if line.startswith(prefix):
            return line[len(prefix):].strip()

    return "UNKNOWN"


def save_result(row):
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    new_file = not RESULTS_FILE.exists()

    with RESULTS_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=FIELDNAMES,
        )

        if new_file:
            writer.writeheader()

        writer.writerow(row)


def finish(row, workflow_start, final_result):
    row["total_duration_seconds"] = round(
        time.perf_counter() - workflow_start,
        2,
    )

    row["final_result"] = final_result

    save_result(row)

    print(f"\n[RESULT] {final_result}")
    print(
        "[METRIC] total_duration_seconds = "
        f"{row['total_duration_seconds']}"
    )

    return 0 if final_result == "PASS" else 1


def main():
    print("==============================================")
    print(" Unauthorized local-user recovery workflow")
    print("==============================================")

    workflow_start = time.perf_counter()

    row = {
        field: "NOT_RUN"
        for field in FIELDNAMES
    }

    row["timestamp_utc"] = datetime.now(
        timezone.utc
    ).isoformat(timespec="seconds")

    row["scenario"] = SCENARIO

    # 1. Detect alert and confirm the malicious user still exists
    print("\n[STEP 1] Detection and active compromise confirmation")

    detection = run_module(
        "controller.wazuh_local_user_alert_check"
    )

    row["wazuh_detection"] = (
        "PASS" if detection["success"] else "FAIL"
    )

    row["detection_check_duration_seconds"] = (
        detection["duration"]
    )

    if not detection["success"]:
        return finish(
            row,
            workflow_start,
            "NO_RECOVERY_TRIGGERED",
        )

    # 2. Capture evidence before destroying the VM
    print("\n[STEP 2] Evidence capture")

    evidence = run_module(
        "controller.capture_local_user_evidence"
    )

    row["evidence_capture"] = (
        "PASS" if evidence["success"] else "FAIL"
    )

    row["evidence_capture_duration_seconds"] = (
        evidence["duration"]
    )

    row["evidence_items_required"] = get_metric(
        evidence["output"],
        "evidence_items_required",
    )

    row["evidence_items_captured"] = get_metric(
        evidence["output"],
        "evidence_items_captured",
    )

    row["evidence_completeness_percentage"] = get_metric(
        evidence["output"],
        "evidence_completeness_percentage",
    )

    if not evidence["success"]:
        return finish(
            row,
            workflow_start,
            "FAILED_EVIDENCE_CAPTURE",
        )

    # 3. Stop the compromised VM
    print("\n[STEP 3] Quarantine")

    quarantine = run_module(
        "controller.quarantine_target"
    )

    row["quarantine"] = (
        "PASS" if quarantine["success"] else "FAIL"
    )

    row["quarantine_duration_seconds"] = (
        quarantine["duration"]
    )

    if not quarantine["success"]:
        return finish(
            row,
            workflow_start,
            "FAILED_QUARANTINE",
        )

    # 4. Remove the old Wazuh agent registration
    print("\n[STEP 4] Remove stale Wazuh agent")

    cleanup = run_module(
        "controller.remove_stale_wazuh_agent"
    )

    row["stale_agent_cleanup"] = (
        "PASS" if cleanup["success"] else "FAIL"
    )

    row["stale_agent_cleanup_duration_seconds"] = (
        cleanup["duration"]
    )

    if not cleanup["success"]:
        return finish(
            row,
            workflow_start,
            "FAILED_STALE_AGENT_CLEANUP",
        )

    # 5. Replace the VM using Terraform
    print("\n[STEP 5] Terraform replacement")

    replacement = run_module(
        "controller.recover_replace"
    )

    row["replacement_recovery"] = (
        "PASS" if replacement["success"] else "FAIL"
    )

    row["replacement_duration_seconds"] = (
        replacement["duration"]
    )

    if not replacement["success"]:
        return finish(
            row,
            workflow_start,
            "FAILED_REPLACEMENT_RECOVERY",
        )

    # 6. Check that the malicious user is gone
    #    and Wazuh/FIM monitoring is restored
    print("\n[STEP 6] Post-recovery validation")

    validation = run_module(
        "controller.validate_local_user_recovery"
    )

    row["post_recovery_validation"] = (
        "PASS" if validation["success"] else "FAIL"
    )

    row["validation_duration_seconds"] = (
        validation["duration"]
    )

    metric_names = [
        "validation_indicators_total",
        "validation_indicators_passed",
        "validation_success_percentage",
        "monitoring_restored",
        "fim_realtime_ready",
        "monitoring_restoration_duration_seconds",
        "residual_compromise_count",
        "residual_compromise_score",
    ]

    for name in metric_names:
        row[name] = get_metric(
            validation["output"],
            name,
        )

    if not validation["success"]:
        return finish(
            row,
            workflow_start,
            "FAILED_POST_RECOVERY_VALIDATION",
        )

    # Mark this alert as processed only after full recovery
    if not mark_selected_alert_processed(SCENARIO):
        return finish(
            row,
            workflow_start,
            "FAILED_ALERT_STATE_UPDATE",
        )

    return finish(
        row,
        workflow_start,
        "PASS",
    )


if __name__ == "__main__":
    raise SystemExit(main())
