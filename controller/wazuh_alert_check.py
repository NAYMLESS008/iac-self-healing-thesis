import subprocess
import sys

from iap_helpers import run_wazuh_command


ATTACK_PATH = "/etc/cron.d/realtime_evil_persistence"
TARGET_AGENT_NAME = "thesis-self-healing-vm"


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result.returncode, result.stdout.strip(), result.stderr.strip()


def wazuh_alert_exists():
    remote_command = (
        f"sudo tail -n 300 /var/ossec/logs/alerts/alerts.json "
        f"| grep '{ATTACK_PATH}' "
        f"| grep 'syscheck' "
        f"| grep 'added' "
        f"| grep '{TARGET_AGENT_NAME}' || true"
    )

    result = run_wazuh_command(remote_command)

    if result["stdout"]:
        print("[WAZUH ALERT FOUND]")
        print(result["stdout"].splitlines()[-1])
        return True

    print("[NO WAZUH ALERT FOUND]")

    if result["stderr"]:
        print("[WAZUH CHECK STDERR]")
        print(result["stderr"])

    return False


def run_recovery_controller():
    print("[ACTION] Running cron self-healing controller...")

    command = [
        sys.executable,
        "controller/cron_self_heal.py"
    ]

    code, stdout, stderr = run_command(command)

    if stdout:
        print(stdout)

    if stderr:
        print(stderr)

    return code == 0


def main():
    print("[1] Checking Wazuh alerts for cron persistence through IAP...")

    if not wazuh_alert_exists():
        print("[STOP] No matching Wazuh alert found. Recovery not triggered.")
        return 1

    print("[2] Wazuh alert confirmed. Triggering recovery...")

    if run_recovery_controller():
        print("[DONE] Alert-driven recovery workflow completed.")
        return 0

    print("[ERROR] Recovery controller failed.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
