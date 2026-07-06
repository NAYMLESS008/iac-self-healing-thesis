import subprocess
import sys


WAZUH_VM_NAME = "wazuh-manager-vm"
WAZUH_ZONE = "europe-west1-b"
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
        f"| grep '{TARGET_AGENT_NAME}'"
    )

    gcloud_command = (
        f'gcloud compute ssh {WAZUH_VM_NAME} '
        f'--zone={WAZUH_ZONE} '
        f'--command "{remote_command}"'
    )

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        gcloud_command
    ]

    code, stdout, stderr = run_command(command)

    if stdout:
        print("[WAZUH ALERT FOUND]")
        print(stdout.splitlines()[-1])
        return True

    print("[NO WAZUH ALERT FOUND]")
    if stderr:
        print(stderr)

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
    print("[1] Checking Wazuh alerts for cron persistence...")

    if not wazuh_alert_exists():
        print("[STOP] No matching Wazuh alert found. Recovery not triggered.")
        return

    print("[2] Wazuh alert confirmed. Triggering recovery...")

    if run_recovery_controller():
        print("[DONE] Alert-driven recovery workflow completed.")
    else:
        print("[ERROR] Recovery controller failed.")


if __name__ == "__main__":
    main()
