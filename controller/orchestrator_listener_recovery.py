from controller.alert_state import mark_selected_alert_processed
import csv
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path


# --- Scenario result file ---
RESULTS_DIR = Path("results")
RESULTS_FILE = (
    RESULTS_DIR
    / "listener_recovery_formal_results.csv"
)


# --- Parse one [METRIC] value printed by a child stage ---
def extract_metric(
    output,
    metric_name,
    default="UNKNOWN",
):
    pattern = (
        rf"^\[METRIC\]\s+"
        rf"{re.escape(metric_name)}"
        rf"\s*=\s*(.+?)\s*$"
    )

    match = re.search(
        pattern,
        output,
        flags=re.MULTILINE,
    )

    if not match:
        return default

    return match.group(1).strip()


# --- Execute one workflow stage and measure its duration ---
def run_step(name, command):
    print(f"\n[STEP] {name}")
    start_time = time.time()

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
    )

    duration = round(
        time.time() - start_time,
        2,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("[STDERR]")
        print(result.stderr)

    if result.returncode == 0:
        print(
            f"[OK] {name} completed in "
            f"{duration} seconds."
        )
    else:
        print(
            f"[FAIL] {name} failed in "
            f"{duration} seconds."
        )

    return {
        "success": result.returncode == 0,
        "return_code": result.returncode,
        "duration": duration,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


# --- Append the completed/partial formal run to the CSV ---
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

    with RESULTS_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fieldnames,
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


# --- Fail closed at a workflow gate and save what happened so far ---
def stop_and_log(
    reason,
    row,
    workflow_start,
):
    row["total_duration_seconds"] = round(
        time.time() - workflow_start,
        2,
    )

    row["final_result"] = reason

    log_result(row)

    print(f"\n[STOP] {reason}")
    print(
        "[METRIC] total_duration_seconds = "
        f"{row['total_duration_seconds']}"
    )

    return 1


def main():
    print(
        "================================================"
    )
    print(
        " Starting unexpected listener recovery "
        "orchestrator "
    )
    print(
        "================================================"
    )

    # --- Initialize the end-to-end timer and formal result row ---
    workflow_start = time.time()

    row = {
        "timestamp_utc": datetime.now(
            timezone.utc
        ).isoformat(timespec="seconds"),
        "scenario": "unexpected_listener",
        "wazuh_detection": "NOT_RUN",
        "detection_check_duration_seconds": "",
        "evidence_capture": "NOT_RUN",
        "evidence_capture_duration_seconds": "",
        "evidence_items_required": "UNKNOWN",
        "evidence_items_captured": "UNKNOWN",
        "evidence_completeness_percentage": "UNKNOWN",
        "quarantine": "NOT_RUN",
        "quarantine_duration_seconds": "",
        "stale_agent_cleanup": "NOT_RUN",
        "stale_agent_cleanup_duration_seconds": "",
        "replacement_recovery": "NOT_RUN",
        "replacement_duration_seconds": "",
        "post_recovery_validation": "NOT_RUN",
        "validation_duration_seconds": "",
        "validation_indicators_total": "UNKNOWN",
        "validation_indicators_passed": "UNKNOWN",
        "validation_success_percentage": "UNKNOWN",
        "monitoring_restored": "NOT_RUN",
        "fim_realtime_ready": "NOT_RUN",
        "monitoring_restoration_duration_seconds": (
            "UNKNOWN"
        ),
        "residual_compromise_count": "UNKNOWN",
        "residual_compromise_score": "UNKNOWN",
        "total_duration_seconds": "",
        "final_result": "",
    }

    # --- Stage 1: Match the Wazuh listener alert and confirm port/process are active ---
    detection = run_step(
        (
            "Wazuh detection and active listener "
            "confirmation"
        ),
        [
            sys.executable,
            "-m",
            "controller.wazuh_listener_alert_check",
            "--check-only",
        ],
    )

    row["wazuh_detection"] = (
        "PASS"
        if detection["success"]
        else "FAIL"
    )

    row[
        "detection_check_duration_seconds"
    ] = detection["duration"]

    if not detection["success"]:
        return stop_and_log(
            "NO_RECOVERY_TRIGGERED",
            row,
            workflow_start,
        )

    # --- Stage 2: Preserve the predefined listener evidence before VM destruction ---
    evidence = run_step(
        "Evidence capture before replacement",
        [
            sys.executable,
            "-m",
            "controller.capture_listener_evidence",
        ],
    )

    row["evidence_capture"] = (
        "PASS"
        if evidence["success"]
        else "FAIL"
    )

    row[
        "evidence_capture_duration_seconds"
    ] = evidence["duration"]

    row["evidence_items_required"] = (
        extract_metric(
            evidence["stdout"],
            "evidence_items_required",
        )
    )

    row["evidence_items_captured"] = (
        extract_metric(
            evidence["stdout"],
            "evidence_items_captured",
        )
    )

    row[
        "evidence_completeness_percentage"
    ] = extract_metric(
        evidence["stdout"],
        "evidence_completeness_percentage",
    )

    # Evidence is a hard gate; replacement does not continue if capture is incomplete.
    if not evidence["success"]:
        return stop_and_log(
            "FAILED_EVIDENCE_CAPTURE",
            row,
            workflow_start,
        )

    # --- Stage 3: Stop the compromised VM ---
    quarantine = run_step(
        "Quarantine compromised target VM",
        [
            sys.executable,
            "-m",
            "controller.quarantine_target",
        ],
    )

    row["quarantine"] = (
        "PASS"
        if quarantine["success"]
        else "FAIL"
    )

    row[
        "quarantine_duration_seconds"
    ] = quarantine["duration"]

    if not quarantine["success"]:
        return stop_and_log(
            "FAILED_QUARANTINE",
            row,
            workflow_start,
        )

    # --- Stage 4: Remove the old Wazuh registration so the replacement can register cleanly ---
    cleanup = run_step(
        "Remove stale Wazuh agent registration",
        [
            sys.executable,
            "-m",
            "controller.remove_stale_wazuh_agent",
        ],
    )

    row["stale_agent_cleanup"] = (
        "PASS"
        if cleanup["success"]
        else "FAIL"
    )

    row[
        "stale_agent_cleanup_duration_seconds"
    ] = cleanup["duration"]

    if not cleanup["success"]:
        return stop_and_log(
            "FAILED_STALE_AGENT_CLEANUP",
            row,
            workflow_start,
        )

    # --- Stage 5: Force Terraform replacement from the trusted IaC definition ---
    replacement = run_step(
        "Terraform replacement recovery",
        [
            sys.executable,
            "-m",
            "controller.recover_replace",
        ],
    )

    row["replacement_recovery"] = (
        "PASS"
        if replacement["success"]
        else "FAIL"
    )

    row[
        "replacement_duration_seconds"
    ] = replacement["duration"]

    if not replacement["success"]:
        return stop_and_log(
            "FAILED_REPLACEMENT_RECOVERY",
            row,
            workflow_start,
        )

    # --- Stage 6: Verify listener artefacts are absent and monitoring is ready ---
    validation = run_step(
        (
            "Post-recovery listener and "
            "monitoring validation"
        ),
        [
            sys.executable,
            "-m",
            "controller.validate_listener_recovery",
        ],
    )

    row["post_recovery_validation"] = (
        "PASS"
        if validation["success"]
        else "FAIL"
    )

    row[
        "validation_duration_seconds"
    ] = validation["duration"]

    # Collect the validator's predefined residual/monitoring metrics.
    row["validation_indicators_total"] = (
        extract_metric(
            validation["stdout"],
            "validation_indicators_total",
        )
    )

    row["validation_indicators_passed"] = (
        extract_metric(
            validation["stdout"],
            "validation_indicators_passed",
        )
    )

    row[
        "validation_success_percentage"
    ] = extract_metric(
        validation["stdout"],
        "validation_success_percentage",
    )

    row["monitoring_restored"] = extract_metric(
        validation["stdout"],
        "monitoring_restored",
        (
            "FAIL"
            if not validation["success"]
            else "UNKNOWN"
        ),
    )

    row["fim_realtime_ready"] = extract_metric(
        validation["stdout"],
        "fim_realtime_ready",
        (
            "FAIL"
            if not validation["success"]
            else "UNKNOWN"
        ),
    )

    row[
        "monitoring_restoration_duration_seconds"
    ] = extract_metric(
        validation["stdout"],
        "monitoring_restoration_duration_seconds",
    )

    row["residual_compromise_count"] = (
        extract_metric(
            validation["stdout"],
            "residual_compromise_count",
        )
    )

    row["residual_compromise_score"] = (
        extract_metric(
            validation["stdout"],
            "residual_compromise_score",
        )
    )

    # --- Finalize the end-to-end result ---
    row["total_duration_seconds"] = round(
        time.time() - workflow_start,
        2,
    )

    row["final_result"] = (
        "PASS"
        if validation["success"]
        else "FAIL"
    )

    # Delay processed-alert marking until the entire recovery has succeeded.
    if validation["success"]:
        mark_selected_alert_processed(
            "unexpected_listener"
        )

    log_result(row)

    if validation["success"]:
        print(
            "\n[SUCCESS] Full unexpected listener "
            "recovery workflow passed."
        )
        print(
            "[METRIC] residual_compromise_count = "
            f"{row['residual_compromise_count']}"
        )
        print(
            "[METRIC] residual_compromise_score = "
            f"{row['residual_compromise_score']}"
        )
        print(
            "[METRIC] monitoring_restored = "
            f"{row['monitoring_restored']}"
        )
        print(
            "[METRIC] fim_realtime_ready = "
            f"{row['fim_realtime_ready']}"
        )
        print(
            "[METRIC] "
            "monitoring_restoration_duration_seconds = "
            f"{row['monitoring_restoration_duration_seconds']}"
        )
        print(
            "[METRIC] total_duration_seconds = "
            f"{row['total_duration_seconds']}"
        )

        return 0

    print(
        "\n[FAIL] Post-recovery validation failed."
    )

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
