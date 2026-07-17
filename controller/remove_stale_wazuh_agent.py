from controller.iap_helpers import run_wazuh_command


TARGET_AGENT_NAME = "thesis-self-healing-vm"


def list_agents():
    return run_wazuh_command("sudo /var/ossec/bin/manage_agents -l", timeout=60)


def remove_agent(agent_id):
    command = f"echo y | sudo /var/ossec/bin/manage_agents -r {agent_id}"
    return run_wazuh_command(command, timeout=60)


def main():
    print("[INFO] Checking Wazuh Manager for stale target agent entry...")

    result = list_agents()

    if not result["success"]:
        print("[ERROR] Failed to list Wazuh agents.")
        print(result["stderr"])
        return 1

    agent_id = None

    for line in result["stdout"].splitlines():
        line = line.strip()

        if f"Name: {TARGET_AGENT_NAME}" in line:
            parts = line.split(",")
            for part in parts:
                part = part.strip()
                if part.startswith("ID:"):
                    agent_id = part.replace("ID:", "").strip()
                    break

    if not agent_id:
        print("[OK] No stale Wazuh agent entry found.")
        return 0

    print(f"[INFO] Removing stale Wazuh agent entry ID: {agent_id}")

    remove_result = remove_agent(agent_id)

    print(remove_result["stdout"])

    if not remove_result["success"]:
        print("[ERROR] Failed to remove stale Wazuh agent entry.")
        print(remove_result["stderr"])
        return 1

    restart_result = run_wazuh_command("sudo systemctl restart wazuh-manager", timeout=60)

    if not restart_result["success"]:
        print("[ERROR] Removed agent but failed to restart Wazuh Manager.")
        print(restart_result["stderr"])
        return 1

    print("[SUCCESS] Stale Wazuh agent entry removed and Wazuh Manager restarted.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
