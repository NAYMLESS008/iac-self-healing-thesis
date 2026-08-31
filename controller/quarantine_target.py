import subprocess
import time
import sys

from controller.iap_helpers import GCLOUD_CMD, PROJECT_ID, ZONE, TARGET_VM


# --- Run local Google Cloud CLI commands ---
def run_command(command):
    result = subprocess.run(
        command,
        capture_output=True,
        text=True
    )

    return result


# --- Read the current GCP power state of the target VM ---
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


# --- Stop-based containment of the compromised VM ---
# The historical file/field name says "quarantine", but the implemented action
# is shutdown-based containment: stop the VM and verify GCP reports TERMINATED.
# It does not place a live VM in an isolated network.
def main():
    print("[INFO] Quarantining compromised target VM...")
    print(f"[INFO] Target VM: {TARGET_VM}")

    before_status = get_target_status()
    print(f"[INFO] Status before quarantine: {before_status}")

    # If it is already stopped, the containment condition is already satisfied.
    if before_status == "TERMINATED":
        print("[OK] Target VM is already quarantined/stopped.")
        return 0

    # Ask Compute Engine to stop the compromised instance.
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

    # Do not treat the stop command itself as enough; poll until the cloud state
    # confirms that attacker-controlled execution has ended on this instance.
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
