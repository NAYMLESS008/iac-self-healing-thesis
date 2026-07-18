import time

from controller.iap_helpers import run_wazuh_command


TARGET_AGENT_NAME = "thesis-self-healing-vm"


def list_agents():
    return run_wazuh_command(
        "sudo /var/ossec/bin/manage_agents -l",
        timeout=60
    )


def extract_agent_id(output):
    for line in output.splitlines():
        line = line.strip()

        if f"Name: {TARGET_AGENT_NAME}" not in line:
            continue

        for part in line.split(","):
            part = part.strip()

            if part.startswith("ID:"):
                return part.replace("ID:", "").strip()

    return None


def remove_agent(agent_id):
    command = (
        f"printf 'y\\n' | "
        f"sudo /var/ossec/bin/manage_agents -r {agent_id}"
    )

    return run_wazuh_command(command, timeout=60)


def wait_for_manager():
    for attempt in range(1, 13):
        result = run_wazuh_command(
            "sudo systemctl is-active wazuh-manager || true",
            timeout=60
        )

        status = result["stdout"].strip()

        print(
            f"[CHECK] Wazuh Manager status "
            f"{attempt}/12: {status or 'UNKNOWN'}"
        )

        if status == "active":
            return True

        if attempt < 12:
            time.sleep(5)

    return False


def main():
    print("[INFO] Checking Wazuh Manager for stale target agent entry...")

    result = list_agents()

    if not result["success"]:
        print("[ERROR] Failed to list Wazuh agents.")
        print(result["stderr"])
        return 1

    agent_id = extract_agent_id(result["stdout"])

    if not agent_id:
        print("[OK] No stale Wazuh agent entry found.")
        return 0

    print(f"[INFO] Removing stale Wazuh agent entry ID: {agent_id}")

    remove_result = remove_agent(agent_id)

    if remove_result["stdout"]:
        print(remove_result["stdout"])

    if remove_result["stderr"]:
        print("[REMOVE STDERR]")
        print(remove_result["stderr"])

    # Do not trust only the interactive command's return code.
    # Verify the actual state on the manager.
    verification_result = list_agents()

    if not verification_result["success"]:
        print("[ERROR] Could not verify stale-agent removal.")
        print(verification_result["stderr"])
        return 1

    remaining_agent_id = extract_agent_id(
        verification_result["stdout"]
    )

    if remaining_agent_id:
        print(
            "[ERROR] Target agent registration still exists "
            f"with ID {remaining_agent_id}."
        )
        return 1

    print("[SUCCESS] Stale Wazuh agent entry removal verified.")

    restart_result = run_wazuh_command(
        "sudo systemctl restart wazuh-manager",
        timeout=90
    )

    if not restart_result["success"]:
        print(
            "[WARNING] Restart command returned a failure status; "
            "checking the actual service state."
        )

        if restart_result["stderr"]:
            print(restart_result["stderr"])

    if not wait_for_manager():
        print("[ERROR] Wazuh Manager did not return to active state.")
        return 1

    print("[SUCCESS] Wazuh Manager is active.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
