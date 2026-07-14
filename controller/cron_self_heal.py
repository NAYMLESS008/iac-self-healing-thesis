import csv
from datetime import datetime, timezone
from pathlib import Path

from iap_helpers import run_target_command


MALICIOUS_CRON = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"
EVIDENCE_DIR = Path("evidence")
RESULTS_FILE = Path("results/experiments.csv")


def run_ssh(command):
    """
    Runs a command on the Terraform-managed target VM through IAP.

    Kept as run_ssh() so the rest of the script does not need major changes.
    """
    result = run_target_command(command)

    return (
        result["return_code"],
        result["stdout"],
        result["stderr"]
    )


def capture_evidence():
    EVIDENCE_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    evidence_file = EVIDENCE_DIR / f"cron_persistence_{timestamp}.txt"

    command = (
        f"sudo sh -c '"
        f"echo === cron evidence ===; "
        f"date; "
        f"echo file: {MALICIOUS_CRON}; "
        f"cat {MALICIOUS_CRON}; "
        f"echo; "
        f"echo stat:; "
        f"stat {MALICIOUS_CRON}"
        f"'"
    )

    code, stdout, stderr = run_ssh(command)

    evidence_file.write_text(stdout + "\n" + stderr, encoding="utf-8")
    return evidence_file, code == 0


def persistence_exists():
    """
    Uses echo instead of raw test exit code.

    This avoids gcloud treating 'file not found' as an SSH failure.
    """
    code, stdout, stderr = run_ssh(
        f"if test -f {MALICIOUS_CRON}; then echo EXISTS; else echo MISSING; fi"
    )

    return "EXISTS" in stdout


def remove_persistence():
    code, stdout, stderr = run_ssh(
        f"sudo rm -f {MALICIOUS_CRON} {PAYLOAD_LOG}"
    )

    return code == 0, stdout, stderr


def validate_clean():
    """
    Uses echo instead of raw test exit code so clean/missing state is handled clearly.
    """
    code, stdout, stderr = run_ssh(
        f"if test ! -f {MALICIOUS_CRON} && test ! -f {PAYLOAD_LOG}; "
        f"then echo CLEAN; else echo NOT_CLEAN; fi"
    )

    return "CLEAN" in stdout


def log_result(status, evidence_path=""):
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    file_exists = RESULTS_FILE.exists()

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp_utc",
                "attack_type",
                "detected_condition",
                "recovery_action",
                "validation_status",
                "evidence_file"
            ])

        writer.writerow([
            datetime.now(timezone.utc).isoformat(),
            "malicious_cron_persistence",
            MALICIOUS_CRON,
            "remove_cron_file",
            status,
            str(evidence_path)
        ])


def main():
    print("[1] Checking for malicious cron persistence through IAP...")

    if not persistence_exists():
        print("[OK] No malicious cron persistence found.")
        log_result("clean_no_action")
        return 0

    print("[ALERT] Malicious cron persistence found.")

    print("[2] Capturing evidence...")
    evidence_file, evidence_ok = capture_evidence()

    if evidence_ok:
        print(f"[OK] Evidence saved to {evidence_file}")
    else:
        print(f"[WARNING] Evidence file created, but remote evidence command had an issue: {evidence_file}")

    print("[3] Removing persistence...")
    removed, stdout, stderr = remove_persistence()

    if not removed:
        print("[ERROR] Recovery failed.")
        if stderr:
            print(stderr)
        log_result("recovery_failed", evidence_file)
        return 2

    print("[4] Validating clean state...")

    if validate_clean():
        print("[SUCCESS] Recovery validation passed.")
        log_result("recovery_validated", evidence_file)
        return 0

    print("[WARNING] Cron file removed, but validation did not fully pass.")
    log_result("partial_validation", evidence_file)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
