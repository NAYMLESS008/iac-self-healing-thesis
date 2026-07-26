import subprocess
import time
from pathlib import Path

from controller.iap_helpers import run_target_command


PROJECT_ROOT = Path(__file__).resolve().parents[1]


def run_command(command):
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode


def get_external_ip():
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

    if result.returncode != 0:
        return ""

    return result.stdout.strip()



def clear_stale_host_key():
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

    command = [
        "terraform",
        "-chdir=Terraform",
        "apply",
        "-replace=google_compute_instance.vm",
        "-auto-approve",
    ]

    code = run_command(command)

    if code != 0:
        print(
            "[ERROR] Terraform replacement failed."
        )
        return 1

    new_ip = get_external_ip()

    print(
        "[2] Terraform replacement completed."
    )
    print(
        f"[OK] New target VM external IP: "
        f"{new_ip}"
    )

    clear_stale_host_key()

    if not wait_for_target_iap():
        return 1

    if not wait_for_wazuh_agent():
        return 1

    print(
        "[SUCCESS] Generic Terraform replacement "
        "completed successfully."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
