import time

from controller.iap_helpers import run_target_command, run_wazuh_command


BACKDOOR_USER = "thesisbackdoor"
TARGET_AGENT_NAME = "thesis-self-healing-vm"

WAZUH_MAX_ATTEMPTS = 12
WAZUH_WAIT_SECONDS = 15


def check_user_artifacts():
    command = (
        "echo === USER CHECK ===; "
        f"if id {BACKDOOR_USER} >/dev/null 2>&1; "
        "then echo USER_PRESENT; "
        "else echo USER_ABSENT; fi; "
        "echo === HOME DIRECTORY CHECK ===; "
        f"if test -d /home/{BACKDOOR_USER}; "
        "then echo HOME_PRESENT; "
        "else echo HOME_ABSENT; fi; "
        "echo === SUDO GROUP CHECK ===; "
        f"if getent group sudo | grep -qw {BACKDOOR_USER}; "
        "then echo SUDO_MEMBERSHIP_PRESENT; "
        "else echo SUDO_MEMBERSHIP_ABSENT; fi"
    )

    return run_target_command(command)


def wait_for_wazuh_restoration():
    print("[CHECK] Waiting for Wazuh monitoring restoration...")

    for attempt in range(1, WAZUH_MAX_ATTEMPTS + 1):
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
            f"[CHECK] Wazuh restoration attempt "
            f"{attempt}/{WAZUH_MAX_ATTEMPTS}: "
            f"local_status={local_status or 'UNKNOWN'}, "
            f"manager_active={manager_active}"
        )

        if local_status == "active" and manager_active:
            print("[SUCCESS] Wazuh monitoring restored.")
            return True

        if attempt < WAZUH_MAX_ATTEMPTS:
            time.sleep(WAZUH_WAIT_SECONDS)

    print("[FAIL] Wazuh monitoring was not restored.")
    return False


def main():
    print("[START] Validating unauthorized local-user recovery")

    result = check_user_artifacts()

    if result["stdout"]:
        print(result["stdout"])

    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"])

    if result["return_code"] != 0:
        print("[FAIL] Could not complete local-user validation.")
        return 1

    stdout = result["stdout"]

    user_absent = "USER_ABSENT" in stdout
    home_absent = "HOME_ABSENT" in stdout
    sudo_membership_absent = "SUDO_MEMBERSHIP_ABSENT" in stdout

    residual_indicators = 0

    if not user_absent:
        residual_indicators += 1

    if not home_absent:
        residual_indicators += 1

    if not sudo_membership_absent:
        residual_indicators += 1

    total_indicators = 3
    residual_score = residual_indicators / total_indicators

    print(
        f"[METRIC] residual_compromise_count = "
        f"{residual_indicators}/{total_indicators}"
    )
    print(f"[METRIC] residual_compromise_score = {residual_score}")

    if residual_indicators != 0:
        print("[FAIL] Unauthorized-user indicators remain.")
        return 1

    if not wait_for_wazuh_restoration():
        return 1

    print("[SUCCESS] Unauthorized local-user persistence is absent.")
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
