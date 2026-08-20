import time

from controller.iap_helpers import run_target_command, run_wazuh_command


BACKDOOR_USER = "thesisbackdoor"
TARGET_AGENT_NAME = "thesis-self-healing-vm"

WAZUH_MAX_ATTEMPTS = 60
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

    restoration_start = time.time()

    for attempt in range(1, WAZUH_MAX_ATTEMPTS + 1):
        target_result = run_target_command(
            "sudo systemctl is-active wazuh-agent || true"
        )

        target_status = target_result["stdout"].strip()

        fim_result = run_target_command(
            "sudo grep -Fq "
            "'Real-time file integrity monitoring started.' "
            "/var/ossec/logs/ossec.log "
            "&& echo FIM_READY || echo FIM_NOT_READY"
        )

        fim_ready = (
            "FIM_READY" in fim_result["stdout"]
            and "FIM_NOT_READY" not in fim_result["stdout"]
        )

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
            f"local_status={target_status or 'UNKNOWN'}, "
            f"manager_active={manager_active}, "
            f"fim_realtime_ready={fim_ready}"
        )

        if (
            target_status == "active"
            and manager_active
            and fim_ready
        ):
            restoration_duration = round(
                time.time() - restoration_start,
                2,
            )

            print("[SUCCESS] Wazuh agent is active locally.")
            print(
                "[SUCCESS] Replacement VM is active "
                "on Wazuh Manager."
            )
            print("[SUCCESS] Real-time FIM monitoring is ready.")
            print("[METRIC] fim_realtime_ready = PASS")
            print(
                "[METRIC] monitoring_restoration_duration_seconds = "
                f"{restoration_duration}"
            )

            return True, restoration_duration

        if attempt < WAZUH_MAX_ATTEMPTS:
            time.sleep(WAZUH_WAIT_SECONDS)

    restoration_duration = round(
        time.time() - restoration_start,
        2,
    )

    print(
        "[FAIL] Wazuh monitoring and real-time FIM were not "
        "fully restored within the wait window."
    )
    print("[METRIC] fim_realtime_ready = FAIL")
    print(
        "[METRIC] monitoring_restoration_duration_seconds = "
        f"{restoration_duration}"
    )

    return False, restoration_duration


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

    required_absent_markers = [
        "USER_ABSENT",
        "HOME_ABSENT",
        "SUDO_MEMBERSHIP_ABSENT",
    ]

    residual_indicators = sum(
        marker not in stdout
        for marker in required_absent_markers
    )

    total_indicators = len(required_absent_markers)

    validation_indicators_passed = (
        total_indicators - residual_indicators
    )

    validation_success_percentage = round(
        (
            validation_indicators_passed
            / total_indicators
        )
        * 100,
        2,
    )

    residual_score = (
        residual_indicators
        / total_indicators
    )

    print(
        "[METRIC] validation_indicators_total = "
        f"{total_indicators}"
    )
    print(
        "[METRIC] validation_indicators_passed = "
        f"{validation_indicators_passed}"
    )
    print(
        "[METRIC] validation_success_percentage = "
        f"{validation_success_percentage}"
    )
    print(
        "[METRIC] residual_compromise_count = "
        f"{residual_indicators}/{total_indicators}"
    )
    print(
        "[METRIC] residual_compromise_score = "
        f"{residual_score}"
    )

    if residual_indicators != 0:
        print(
            "[FAIL] Unauthorized local-user persistence "
            "indicators remain after recovery."
        )
        return 1

    (
        monitoring_restored,
        monitoring_restoration_duration,
    ) = wait_for_wazuh_restoration()

    if not monitoring_restored:
        return 1

    print("[SUCCESS] Unauthorized local-user persistence is absent.")
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
