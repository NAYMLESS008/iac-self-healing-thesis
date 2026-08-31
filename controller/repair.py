import json
import os
import subprocess
import sys
from pathlib import Path

# --- Project paths used by the older in-place SSH-key repair helper ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILE = PROJECT_ROOT / "controller" / "baseline.json"
TERRAFORM_DIR = PROJECT_ROOT / "Terraform"
CLEAN_KEYS_FILE = PROJECT_ROOT / "controller" / "clean_authorized_keys.tmp"


# --- Run a local command and stop if the repair command fails ---
def run_command(command):
    result = subprocess.run(
        command,
        capture_output=False,
        text=True
    )

    if result.returncode != 0:
        print("[ERROR] Command failed:")
        print(" ".join(command))
        sys.exit(1)


# --- Read the target VM external IP from Terraform output ---
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

    return result.stdout.strip()


# --- Build a local clean authorized_keys file from the trusted baseline ---
def write_clean_authorized_keys(allowed_keys):
    with open(CLEAN_KEYS_FILE, "w", encoding="utf-8") as file:
        for key in allowed_keys:
            file.write(key.strip() + "\n")

    print(f"[INFO] Clean authorized_keys file created: {CLEAN_KEYS_FILE}")


# --- Copy the clean file to the VM and restore secure permissions ---
def repair_authorized_keys(vm_user, vm_ip):
    private_key = Path(os.environ["USERPROFILE"]) / ".ssh" / "gcp_thesis_vm"

    remote_path = f"{vm_user}@{vm_ip}:/home/{vm_user}/.ssh/authorized_keys"

    print("[INFO] Copying clean authorized_keys to VM...")

    run_command([
        "scp",
        "-i",
        str(private_key),
        str(CLEAN_KEYS_FILE),
        remote_path
    ])

    print("[INFO] Fixing authorized_keys permissions...")

    run_command([
        "ssh",
        "-i",
        str(private_key),
        f"{vm_user}@{vm_ip}",
        "chmod 600 ~/.ssh/authorized_keys"
    ])


def main():
    print("=== Self-Healing Repair: SSH Authorized Keys ===")

    # --- Load the trusted key baseline and target user ---
    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    vm_user = baseline["vm_user"]
    allowed_keys = baseline["allowed_ssh_keys"]

    print("[INFO] Getting VM IP from Terraform...")
    vm_ip = get_vm_ip_from_terraform()
    print(f"[INFO] VM IP: {vm_ip}")

    # --- Perform the in-place authorized_keys repair ---
    write_clean_authorized_keys(allowed_keys)
    repair_authorized_keys(vm_user, vm_ip)

    print()
    print("[REPAIR COMPLETE] authorized_keys has been restored to the trusted baseline.")


if __name__ == "__main__":
    main()