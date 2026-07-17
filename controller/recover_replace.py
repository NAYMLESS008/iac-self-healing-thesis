import subprocess
import time
from pathlib import Path

from controller.iap_helpers import run_target_command


PROJECT_ROOT = Path(__file__).resolve().parents[1]
TERRAFORM_DIR = PROJECT_ROOT / "Terraform"

MALICIOUS_CRON = "/etc/cron.d/realtime_evil_persistence"


def run_command(command):
    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    return result.returncode


def get_external_ip():
    result = subprocess.run(
        ["terraform", "-chdir=Terraform", "output", "-raw", "external_ip"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        return ""

    return result.stdout.strip()


def wait_for_target_iap(max_attempts=12, wait_seconds=10):
    """
    Waits until the replacement target VM is reachable through IAP.
    """
    print("[3] Waiting for replacement VM to become reachable through IAP...")

    for attempt in range(1, max_attempts + 1):
        print(f"[CHECK] IAP reachability attempt {attempt}/{max_attempts}...")

        result = run_target_command("hostname", timeout=180)

        if result["success"] and "thesis-self-healing-vm" in result["stdout"]:
            print("[OK] Replacement target VM is reachable through IAP.")
            return True

        time.sleep(wait_seconds)

    print("[ERROR] Replacement target VM did not become reachable through IAP in time.")
    return False


def validate_cron_removed():
    """
    Confirms the malicious cron persistence file does not exist on the replacement VM.
    """
    print("[4] Validating malicious cron persistence is absent...")

    result = run_target_command(
        f"if test ! -f {MALICIOUS_CRON}; then echo CLEAN; else echo NOT_CLEAN; fi"
    )

    if "CLEAN" in result["stdout"]:
        print("[OK] Malicious cron persistence is absent.")
        return True

    print("[ERROR] Malicious cron persistence still exists after replacement.")
    print(result["stdout"])
    print(result["stderr"])
    return False


def validate_wazuh_agent():
    """
    Confirms Wazuh agent is active on the replacement VM.
    """
    print("[5] Validating Wazuh agent is active on replacement VM...")

    result = run_target_command("sudo systemctl is-active wazuh-agent || true")

    if "active" in result["stdout"]:
        print("[OK] Wazuh agent is active.")
        return True

    print("[ERROR] Wazuh agent is not active yet.")
    print(result["stdout"])
    print(result["stderr"])
    return False


def main():
    print("[1] Starting Terraform replacement recovery for target VM only...")

    command = [
        "terraform",
        "-chdir=Terraform",
        "apply",
        "-replace=google_compute_instance.vm",
        "-auto-approve"
    ]

    code = run_command(command)

    if code != 0:
        print("[ERROR] Terraform replacement failed.")
        raise SystemExit(1)

    new_ip = get_external_ip()

    print("[2] Terraform replacement completed.")
    print(f"[OK] New target VM external IP: {new_ip}")

    if not wait_for_target_iap():
        raise SystemExit(1)

    cron_clean = validate_cron_removed()
    wazuh_active = validate_wazuh_agent()

    if cron_clean and wazuh_active:
        print("[SUCCESS] Replacement recovery validation passed.")
        raise SystemExit(0)

    print("[ERROR] Replacement recovery validation failed.")
    raise SystemExit(1)


if __name__ == "__main__":
    main()
