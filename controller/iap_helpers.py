import subprocess
import time
from pathlib import Path


# --- Shared Google Cloud / IAP connection settings ---
# These values are reused whenever the controller runs a command on either VM.
GCLOUD_CMD = r"C:\Program Files (x86)\Google\Cloud SDK\google-cloud-sdk\bin\gcloud.cmd"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"

WAZUH_VM = "wazuh-manager-vm"
TARGET_VM = "thesis-self-healing-vm"


# --- Run one remote command through Google Cloud IAP-assisted SSH ---
def run_iap_command(vm_name, remote_command, timeout=120):
    # Build the gcloud SSH command. --tunnel-through-iap is the administrative
    # transport used by the external controller; it is not the Wazuh telemetry path.
    command = [
        GCLOUD_CMD,
        "compute",
        "ssh",
        vm_name,
        f"--zone={ZONE}",
        f"--project={PROJECT_ID}",
        "--tunnel-through-iap",
        f"--command={remote_command}",
    ]

    try:
        start_time = time.time()

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        duration = round(time.time() - start_time, 2)

        # Return one consistent result dictionary so every controller module can
        # check success, output and timing in the same way.
        return {
            "success": result.returncode == 0,
            "return_code": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "duration": duration,
            "timed_out": False,
        }

    except subprocess.TimeoutExpired as e:
        duration = round(timeout, 2)

        # A timeout is explicit failure/unknown state; empty output is not
        # interpreted as proof that an artefact is absent.
        return {
            "success": False,
            "return_code": 124,
            "stdout": e.stdout or "",
            "stderr": f"IAP command timed out after {timeout} seconds",
            "duration": duration,
            "timed_out": True,
        }


# --- Convenience wrapper for commands on the trusted Wazuh Manager ---
def run_wazuh_command(remote_command, timeout=120):
    """
    Runs a command on the Wazuh Manager VM.
    """
    return run_iap_command(WAZUH_VM, remote_command, timeout)


# --- Convenience wrapper for commands on the evaluated target VM ---
def run_target_command(remote_command, timeout=120):
    """
    Runs a command on the Terraform-managed target VM.
    """
    return run_iap_command(TARGET_VM, remote_command, timeout)
