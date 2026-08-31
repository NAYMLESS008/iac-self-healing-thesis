import json
import os
import subprocess
import sys
from pathlib import Path

# Project paths
# --- Project files used by the baseline monitor ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]
BASELINE_FILE = PROJECT_ROOT / "controller" / "baseline.json"
TERRAFORM_DIR = PROJECT_ROOT / "terraform"


# --- Run a local command and stop immediately if it fails ---
def run_command(command):
    """
    Runs a command on Windows and returns the output.
    If the command fails, the script stops and shows the error.
    """
    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        shell=True
    )

    if result.returncode != 0:
        print("[ERROR] Command failed:")
        print(command)
        print(result.stderr)
        sys.exit(1)

    return result.stdout.strip()


# --- Ask Terraform for the current target VM IP instead of hardcoding it ---
def get_vm_ip_from_terraform():
    """
    Asks Terraform for the VM external IP.
    This avoids hardcoding the VM IP in Python.
    """
    command = f'terraform -chdir="{TERRAFORM_DIR}" output -raw external_ip'
    return run_command(command)


# --- Read the VM's live authorized_keys file over SSH ---
def get_authorized_keys(vm_user, vm_ip):
    """
    Uses SSH to read ~/.ssh/authorized_keys from the VM.
    This is the live runtime state we are monitoring.
    """
    private_key = Path(os.environ["USERPROFILE"]) / ".ssh" / "gcp_thesis_vm"

    command = (
        f'ssh -i "{private_key}" '
        f'{vm_user}@{vm_ip} '
        f'"cat ~/.ssh/authorized_keys"'
    )

    output = run_command(command)

    keys = []
    for line in output.splitlines():
        line = line.strip()

        # Ignore empty lines and Google-added comment lines.
        # Ignore empty lines and Google-added comment lines before comparison.
        if not line or line.startswith("#"):
            continue

        keys.append(line)

    return keys


def main():
    print("=== Self-Healing Monitor: SSH Authorized Keys Check ===")

    # --- Load the trusted SSH-key baseline ---
    with open(BASELINE_FILE, "r", encoding="utf-8") as file:
        baseline = json.load(file)

    vm_user = baseline["vm_user"]
    allowed_keys = baseline["allowed_ssh_keys"]

    print(f"[INFO] VM user: {vm_user}")
    print("[INFO] Getting VM IP from Terraform...")

    vm_ip = get_vm_ip_from_terraform()
    print(f"[INFO] VM IP: {vm_ip}")

    print("[INFO] Reading current authorized_keys from VM...")
    current_keys = get_authorized_keys(vm_user, vm_ip)

    # --- Compare runtime SSH keys with the trusted baseline ---
    extra_keys = [key for key in current_keys if key not in allowed_keys]
    missing_keys = [key for key in allowed_keys if key not in current_keys]

    print()
    print("=== Result ===")

    if not extra_keys and not missing_keys:
        print("[CLEAN] VM SSH keys match the trusted baseline.")
    else:
        print("[DRIFT DETECTED] VM SSH keys do not match the baseline.")

        if extra_keys:
            print()
            print("Extra unauthorized keys found:")
            for key in extra_keys:
                print(f"- {key}")

        if missing_keys:
            print()
            print("Approved baseline keys missing:")
            for key in missing_keys:
                print(f"- {key}")


if __name__ == "__main__":
    main()