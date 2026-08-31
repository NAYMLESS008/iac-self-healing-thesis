import subprocess
import time
from pathlib import Path

from controller.iap_helpers import run_target_command


# Project root is used as the working directory for Terraform and SSH-related commands.
PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_command(command):
    # Run a local command from the project root and capture its output.
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    # Show Terraform/command output in the controller console for traceability.
    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    # Return only the process exit code so the caller can decide PASS/FAIL.
    return result.returncode


def get_external_ip():
    # Ask Terraform for the external_ip output of the newly created target VM.
    result = subprocess.run(
        [
            "terraform",
            "-chdir=Terraform",
            "output",
            "-raw",
            "external_ip",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    # A non-zero Terraform exit code means the output could not be read.
    if result.returncode != 0:
        return ""

    return result.stdout.strip()



def clear_stale_host_key():
    # Replacement creates a new VM instance, so remove any cached SSH host-key entry
    # for the old target before attempting administrative access to the replacement.
    result = subprocess.run(
        [
            "ssh-keygen",
            "-R",
            "thesis-self-healing-vm",
        ],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    print("[OK] Cleared stale SSH host-key entries.")


def wait_for_target_iap(
    max_attempts=12,
    wait_seconds=10,
):
    # Terraform finishing does not guarantee the guest is immediately reachable.
    # Poll the replacement VM through the same IAP-assisted admin path used by the controller.
    print(
        "[3] Waiting for replacement VM "
        "to become reachable through IAP..."
    )

    for attempt in range(
        1,
        max_attempts + 1,
    ):
        print(
            f"[CHECK] IAP reachability attempt "
            f"{attempt}/{max_attempts}..."
        )

        # 'hostname' is a lightweight positive check that the expected VM is reachable.
        result = run_target_command(
            "hostname",
            timeout=180,
        )

        if (
            result["success"]
            and "thesis-self-healing-vm"
            in result["stdout"]
        ):
            print(
                "[OK] Replacement target VM is "
                "reachable through IAP."
            )
            return True

        if attempt < max_attempts:
            time.sleep(wait_seconds)

    print(
        "[ERROR] Replacement target VM did not "
        "become reachable through IAP in time."
    )
    return False


def wait_for_wazuh_agent(
    max_attempts=12,
    wait_seconds=15,
):
    # Poll the replacement guest until its local Wazuh agent service reports active.
    # This is a service-readiness check, not the final FIM-readiness validation.
    print(
        "[4] Waiting for local Wazuh agent "
        "to become active..."
    )

    for attempt in range(
        1,
        max_attempts + 1,
    ):
        result = run_target_command(
            "sudo systemctl is-active "
            "wazuh-agent || true"
        )

        status = result["stdout"].strip()

        print(
            f"[CHECK] Wazuh agent status "
            f"{attempt}/{max_attempts}: "
            f"{status or 'UNKNOWN'}"
        )

        if status == "active":
            print(
                "[OK] Wazuh agent is active "
                "on the replacement VM."
            )
            return True

        if attempt < max_attempts:
            time.sleep(wait_seconds)

    print(
        "[ERROR] Wazuh agent did not become "
        "active in time."
    )
    return False


def main():
    print(
        "[1] Starting Terraform replacement "
        "recovery for target VM..."
    )

    # Core IaC replacement command used in the thesis report:
    # -chdir=Terraform: run Terraform using the project Terraform directory.
    # apply: create the infrastructure changes in the real GCP environment.
    # -replace=...: force recreation of the target VM even when Terraform sees no config drift.
    # -auto-approve: skip a second Terraform prompt after the human has started the controller.
    command = [
        "terraform",
        "-chdir=Terraform",
        "apply",
        "-replace=google_compute_instance.vm",
        "-auto-approve",
    ]

    code = run_command(command)

    # Terraform replacement is mandatory; stop this stage if apply failed.
    if code != 0:
        print(
            "[ERROR] Terraform replacement failed."
        )
        return 1

    # Read the replacement VM's current external IP from Terraform output.
    new_ip = get_external_ip()

    print(
        "[2] Terraform replacement completed."
    )
    print(
        f"[OK] New target VM external IP: "
        f"{new_ip}"
    )

    clear_stale_host_key()

    # A successful Terraform apply is only an intermediate milestone.
    # The controller still requires the replacement VM to become administratively reachable.
    if not wait_for_target_iap():
        return 1

    # Confirm the local Wazuh agent service has started on the replacement.
    if not wait_for_wazuh_agent():
        return 1

    print(
        "[SUCCESS] Generic Terraform replacement "
        "completed successfully."
    )
    return 0


if __name__ == "__main__":
    # Propagate main()'s numeric return value as the script exit code.
    raise SystemExit(main())
