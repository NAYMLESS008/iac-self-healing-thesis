import csv
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path


MALICIOUS_CRON = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"
EVIDENCE_DIR = Path("evidence")
RESULTS_FILE = Path("results/experiments.csv")


def run_ssh(command):
    vm_ip = subprocess.check_output(
        ["terraform", "-chdir=Terraform", "output", "-raw", "external_ip"],
        text=True
    ).strip()

    ssh_key = os.path.expanduser("~/.ssh/gcp_thesis_vm")

    result = subprocess.run(
        ["ssh", "-o", "StrictHostKeyChecking=accept-new", "-i", ssh_key, f"thesisadmin@{vm_ip}", command],
        capture_output=True,
        text=True
    )

    return result.returncode, result.stdout.strip(), result.stderr.strip()


def capture_evidence():
    EVIDENCE_DIR.mkdir(exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    evidence_file = EVIDENCE_DIR / f"cron_persistence_{timestamp}.txt"

    command = f"sudo sh -c 'echo === cron evidence ===; date; echo file: {MALICIOUS_CRON}; cat {MALICIOUS_CRON}; echo; echo stat:; stat {MALICIOUS_CRON}'"
    code, stdout, stderr = run_ssh(command)

    evidence_file.write_text(stdout + "\n" + stderr, encoding="utf-8")
    return evidence_file, code == 0


def persistence_exists():
    code, stdout, stderr = run_ssh(f"test -f {MALICIOUS_CRON}")
    return code == 0


def remove_persistence():
    code, stdout, stderr = run_ssh(f"sudo rm -f {MALICIOUS_CRON} {PAYLOAD_LOG}")
    return code == 0, stdout, stderr


def validate_clean():
    code, stdout, stderr = run_ssh(
        f"test ! -f {MALICIOUS_CRON} && test ! -f {PAYLOAD_LOG}"
    )
    return code == 0


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
    print("[1] Checking for malicious cron persistence...")

    if not persistence_exists():
        print("[OK] No malicious cron persistence found.")
        log_result("clean_no_action")
        return

    print("[ALERT] Malicious cron persistence found.")

    print("[2] Capturing evidence...")
    evidence_file, evidence_ok = capture_evidence()
    print(f"[OK] Evidence saved to {evidence_file}")

    print("[3] Removing persistence...")
    removed, stdout, stderr = remove_persistence()

    if not removed:
        print("[ERROR] Recovery failed.")
        print(stderr)
        log_result("recovery_failed", evidence_file)
        return

    print("[4] Validating clean state...")
    if validate_clean():
        print("[SUCCESS] Recovery validation passed.")
        log_result("recovery_validated", evidence_file)
    else:
        print("[WARNING] Cron file removed, but validation did not fully pass.")
        log_result("partial_validation", evidence_file)


if __name__ == "__main__":
    main()
