import subprocess
import time
import sys

from controller.iap_helpers import GCLOUD_CMD, PROJECT_ID, ZONE, TARGET_VM


def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result


def get_target_status():
    result = run_command([
        GCLOUD_CMD,
        "compute",
        "instances",
        "describe",
        TARGET_VM,
        "--zone", ZONE,
        "--project", PROJECT_ID,
        "--format=value(status)"
    ])

    if result.returncode != 0:
        print("[ERROR] Could not get target VM status.")
        print(result.stderr)
        return None

    return result.stdout.strip()


def main():
    print("[INFO] Quarantining compromised target VM...")
    print(f"[INFO] Target VM: {TARGET_VM}")

    before_status = get_target_status()
    print(f"[INFO] Status before quarantine: {before_status}")

    if before_status == "TERMINATED":
        print("[OK] Target VM is already quarantined/stopped.")
        return 0

    result = run_command([
        GCLOUD_CMD,
        "compute",
        "instances",
        "stop",
        TARGET_VM,
        "--zone", ZONE,
        "--project", PROJECT_ID,
        "--quiet"
    ])

    if result.returncode != 0:
        print("[ERROR] Failed to stop target VM.")
        print(result.stderr)
        return 1

    for attempt in range(1, 13):
        status = get_target_status()
        print(f"[CHECK] Quarantine status attempt {attempt}/12: {status}")

        if status == "TERMINATED":
            print("[SUCCESS] Target VM quarantined successfully.")
            return 0

        time.sleep(5)

    print("[ERROR] Target VM did not reach TERMINATED state in time.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
