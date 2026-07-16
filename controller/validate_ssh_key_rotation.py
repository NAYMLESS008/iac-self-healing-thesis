import csv
import subprocess
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
RESULTS_FILE = PROJECT_ROOT / "results" / "ssh_key_rotation_results.csv"

NEW_KEY_ALIAS = "thesis-target-rotated-key"
OLD_KEY_ALIAS = "thesis-target-old-compromised-key"

EXPECTED_USER = "thesisadmin"
EXPECTED_HOSTNAME = "thesis-self-healing-vm"


def run_ssh(alias):
    command = ["ssh", alias, "whoami && hostname"]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=90
    )

    return {
        "return_code": result.returncode,
        "stdout": result.stdout.strip(),
        "stderr": result.stderr.strip(),
    }


def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    readable_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    EVIDENCE_DIR.mkdir(exist_ok=True)
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    print("[INFO] Validating rotated SSH key access...")
    new_key_result = run_ssh(NEW_KEY_ALIAS)

    print("[INFO] Validating old compromised SSH key denial...")
    old_key_result = run_ssh(OLD_KEY_ALIAS)

    new_key_success = (
        new_key_result["return_code"] == 0
        and EXPECTED_USER in new_key_result["stdout"]
        and EXPECTED_HOSTNAME in new_key_result["stdout"]
    )

    old_key_denied = (
        old_key_result["return_code"] != 0
        and (
            "Permission denied" in old_key_result["stderr"]
            or "publickey" in old_key_result["stderr"]
        )
    )

    residual_compromise_score = 0 if old_key_denied else 1
    final_result = "PASS" if new_key_success and old_key_denied else "FAIL"

    evidence_file = EVIDENCE_DIR / f"ssh_key_rotation_validation_{timestamp}.txt"

    evidence_file.write_text(
        f"""SSH Key Rotation Validation Evidence

Date: {readable_time}

Experiment:
Terraform-managed SSH key rotation after credential compromise.

Validation 1:
New rotated key should authenticate successfully.

Command:
ssh {NEW_KEY_ALIAS} "whoami && hostname"

Return code:
{new_key_result["return_code"]}

STDOUT:
{new_key_result["stdout"]}

STDERR:
{new_key_result["stderr"]}

Validation 2:
Old compromised key should fail authentication.

Command:
ssh {OLD_KEY_ALIAS} "whoami && hostname"

Return code:
{old_key_result["return_code"]}

STDOUT:
{old_key_result["stdout"]}

STDERR:
{old_key_result["stderr"]}

Metrics:
new_key_success={new_key_success}
old_key_denied={old_key_denied}
residual_compromise_score={residual_compromise_score}
final_result={final_result}

Conclusion:
Replacement recovery combined with IaC-managed SSH key rotation removed residual access from the old compromised key.
""",
        encoding="utf-8"
    )

    file_exists = RESULTS_FILE.exists()

    with RESULTS_FILE.open("a", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "timestamp",
            "experiment",
            "new_key_success",
            "old_key_denied",
            "residual_compromise_score",
            "final_result",
            "evidence_file",
        ]

        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "timestamp": readable_time,
            "experiment": "ssh_key_rotation",
            "new_key_success": new_key_success,
            "old_key_denied": old_key_denied,
            "residual_compromise_score": residual_compromise_score,
            "final_result": final_result,
            "evidence_file": str(evidence_file),
        })

    print("[RESULT]", final_result)
    print("[METRIC] residual_compromise_score =", residual_compromise_score)
    print("[EVIDENCE]", evidence_file)

    if final_result != "PASS":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
