import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILE = PROJECT_ROOT / "controller" / "baseline.json"
TERRAFORM_DIR = PROJECT_ROOT / "Terraform"
ATTACKER_KEY = PROJECT_ROOT / "attacks" / "attacker_key"


def get_vm_ip_from_terraform():
    result = subprocess.run(
        ["terraform", f"-chdir={TERRAFORM_DIR}", "output", "-raw", "external_ip"],
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        print("[ERROR] Could not get VM IP from Terraform.")
        print(result.stderr)
        sys.exit(1)

    vm_ip = result.stdout.strip()

    if not vm_ip:
        print("[ERROR] No VM IP found. The VM may have been destroyed.")
        print("[INFO] Recreate it with: cd C:\\iac-self-healing-thesis\\Terraform && terraform apply")
        sys.exit(1)

    return vm_ip
        


def test_attacker_access(vm_user, vm_ip):
    command = [
        "ssh",
        "-i",
        str(ATTACKER_KEY),
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        f"{vm_user}@{vm_ip}",
        "echo ATTACKER_ACCESS_WORKS"
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    print("=== Attacker Access Test ===")

    if "ATTACKER_ACCESS_WORKS" in stdout:
        print("[VALIDATION FAILED] Attacker key can still log in.")
        print("[RISK] Repair did not fully remove attacker access.")
        return False

    if "Permission denied" in stderr or result.returncode != 0:
        print("[VALIDATION PASSED] Attacker key cannot log in.")
        print("[SECURITY RESTORED] Unauthorized SSH access has been removed.")
        return True

    print("[UNKNOWN RESULT] SSH test did not behave as expected.")
    print("STDOUT:", stdout)
    print("STDERR:", stderr)
    return False


def main():
    print("=== Self-Healing Validation: Attacker SSH Access ===")

    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    vm_user = baseline["vm_user"]

    print("[INFO] Getting VM IP from Terraform...")
    vm_ip = get_vm_ip_from_terraform()
    print(f"[INFO] VM IP: {vm_ip}")

    success = test_attacker_access(vm_user, vm_ip)

    print()
    if success:
        print("[FINAL RESULT] Recovery validation successful.")
    else:
        print("[FINAL RESULT] Recovery validation failed.")
        sys.exit(1)


if __name__ == "__main__":
    main()