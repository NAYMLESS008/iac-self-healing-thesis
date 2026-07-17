import csv
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path


RESULTS_DIR = Path("results")
RESULTS_FILE = RESULTS_DIR / "ssh_key_recovery_orchestrator_results.csv"


def run_step(name, command):
    print(f"\n[STEP] {name}")
    start = time.time()

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    duration = round(time.time() - start, 2)

    print(result.stdout)

    if result.stderr:
        print("[STDERR]")
        print(result.stderr)

    if result.returncode == 0:
        print(f"[OK] {name} completed in {duration} seconds.")
    else:
        print(f"[FAIL] {name} failed in {duration} seconds.")

    return {
        "name": name,
        "success": result.returncode == 0,
        "return_code": result.returncode,
        "duration": duration,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def log_result(row):
    RESULTS_DIR.mkdir(exist_ok=True)

    file_exists = RESULTS_FILE.exists()

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=[
                "timestamp",
                "scenario",
                "wazuh_detection",
                "evidence_capture",
                "quarantine",
                "stale_agent_cleanup",
                "replacement_recovery",
                "post_recovery_validation",
                "residual_compromise_score",
                "total_duration_seconds",
                "final_result",
            ]
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow(row)


def stop_and_log(reason, row, workflow_start):
    row["total_duration_seconds"] = round(time.time() - workflow_start, 2)
    row["final_result"] = reason
    log_result(row)
    print(f"[STOP] {reason}")
    return 1


def main():
    print("[START] SSH key persistence recovery orchestrator")
    workflow_start = time.time()

    row = {
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "scenario": "ssh_key_persistence",
        "wazuh_detection": "NOT_RUN",
        "evidence_capture": "NOT_RUN",
        "quarantine": "NOT_RUN",
        "stale_agent_cleanup": "NOT_RUN",
        "replacement_recovery": "NOT_RUN",
        "post_recovery_validation": "NOT_RUN",
        "residual_compromise_score": "UNKNOWN",
        "total_duration_seconds": "",
        "final_result": "",
    }

    detection = run_step(
        "Wazuh detection and active old-key confirmation",
        [sys.executable, "-m", "controller.wazuh_ssh_key_alert_check"]
    )

    row["wazuh_detection"] = "PASS" if detection["success"] else "FAIL"

    if not detection["success"]:
        return stop_and_log("NO_RECOVERY_TRIGGERED", row, workflow_start)

    evidence = run_step(
        "Evidence capture before replacement",
        [sys.executable, "-m", "controller.capture_ssh_key_evidence"]
    )

    row["evidence_capture"] = "PASS" if evidence["success"] else "FAIL"

    if not evidence["success"]:
        return stop_and_log("FAILED_EVIDENCE_CAPTURE", row, workflow_start)

    quarantine = run_step(
        "Quarantine compromised target VM",
        [sys.executable, "-m", "controller.quarantine_target"]
    )

    row["quarantine"] = "PASS" if quarantine["success"] else "FAIL"

    if not quarantine["success"]:
        return stop_and_log("FAILED_QUARANTINE", row, workflow_start)

    cleanup = run_step(
        "Remove stale Wazuh agent entry",
        [sys.executable, "-m", "controller.remove_stale_wazuh_agent"]
    )

    row["stale_agent_cleanup"] = "PASS" if cleanup["success"] else "FAIL"

    if not cleanup["success"]:
        return stop_and_log("FAILED_STALE_AGENT_CLEANUP", row, workflow_start)

    replacement = run_step(
        "Terraform replacement recovery",
        [sys.executable, "-m", "controller.recover_replace"]
    )

    row["replacement_recovery"] = "PASS" if replacement["success"] else "FAIL"

    validation = run_step(
        "Post-recovery SSH key validation",
        [sys.executable, "-m", "controller.validate_ssh_key_rotation"]
    )

    row["post_recovery_validation"] = "PASS" if validation["success"] else "FAIL"

    final_success = (
        detection["success"]
        and evidence["success"]
        and quarantine["success"]
        and cleanup["success"]
        and replacement["success"]
        and validation["success"]
    )

    row["residual_compromise_score"] = 0 if validation["success"] else "UNKNOWN"
    row["total_duration_seconds"] = round(time.time() - workflow_start, 2)
    row["final_result"] = "PASS" if final_success else "FAIL"

    log_result(row)

    if final_success:
        print("\n[SUCCESS] Full SSH key persistence recovery workflow passed.")
        print("[METRIC] residual_compromise_score = 0")
        return 0

    print("\n[FAIL] SSH key persistence recovery workflow failed.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
