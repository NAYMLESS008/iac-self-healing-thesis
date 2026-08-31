import time

from controller.iap_helpers import (
    run_target_command,
    run_wazuh_command,
)


# --- Monitoring restoration settings ---
TARGET_AGENT_NAME = "thesis-self-healing-vm"
MAX_ATTEMPTS = 12
WAIT_SECONDS = 15


def main():
    print("[START] Validating Wazuh monitoring restoration")

    # --- Poll both sides of the Wazuh connection after VM replacement ---
    # Local check: the replacement VM's wazuh-agent service is running.
    # Manager check: the manager lists the replacement target as Active.
    for attempt in range(1, MAX_ATTEMPTS + 1):
        target_result = run_target_command(
            "sudo systemctl is-active wazuh-agent || true"
        )

        local_status = target_result["stdout"].strip()

        manager_result = run_wazuh_command(
            "sudo /var/ossec/bin/agent_control -l"
        )

        manager_active = (
            TARGET_AGENT_NAME in manager_result["stdout"]
            and "Active" in manager_result["stdout"]
        )

        print(
            f"[CHECK] Monitoring restoration "
            f"{attempt}/{MAX_ATTEMPTS}: "
            f"local_status={local_status or 'UNKNOWN'}, "
            f"manager_active={manager_active}"
        )

        # Both checks must succeed before basic monitoring restoration passes.
        if local_status == "active" and manager_active:
            print("[SUCCESS] Wazuh monitoring restored.")
            return 0

        if attempt < MAX_ATTEMPTS:
            time.sleep(WAIT_SECONDS)

    print("[FAIL] Wazuh monitoring was not restored.")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
