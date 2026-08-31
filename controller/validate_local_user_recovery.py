import time

from controller.iap_helpers import run_target_command, run_wazuh_command


# Controlled backdoor account created by the local-user scenario.
BACKDOOR_USER = "thesisbackdoor"
# Expected replacement-agent name used in manager-side monitoring checks.
TARGET_AGENT_NAME = "thesis-self-healing-vm"

# Monitoring-restoration polling limits used by the final protocol.
WAZUH_MAX_ATTEMPTS = 60
WAZUH_WAIT_SECONDS = 15


def check_user_artifacts():
    # Listing 4 in the report: check three separate residual conditions.
    # The account, its home directory, and sudo-group membership must all be absent.
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

    # Execute all three explicit checks on the replacement VM.
    return run_target_command(command)


def wait_for_wazuh_restoration():
    # Security-state validation alone is not enough for final recovery acceptance;
    # the replacement also has to regain the required monitoring state.
    print("[CHECK] Waiting for Wazuh monitoring restoration...")

    restoration_start = time.time()

    for attempt in range(1, WAZUH_MAX_ATTEMPTS + 1):
        # Check 1: Wazuh agent service is active locally on the replacement target.
        target_result = run_target_command(
            "sudo systemctl is-active wazuh-agent || true"
        )

        target_status = target_result["stdout"].strip()

        # Check 2: the replacement agent log contains the study-specific real-time FIM marker.
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

        # Check 3: the trusted Wazuh Manager sees the replacement agent as Active.
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

        # Final monitoring readiness requires all three conditions simultaneously.
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

    # Polling expired before all required monitoring conditions became true.
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

    # Run the three attack-specific post-recovery checks first.
    result = check_user_artifacts()

    if result["stdout"]:
        print(result["stdout"])

    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"])

    # A failed/indeterminate remote command cannot be treated as successful absence.
    if result["return_code"] != 0:
        print("[FAIL] Could not complete local-user validation.")
        return 1

    stdout = result["stdout"]

    # These explicit ABSENT markers define the three local-user acceptance checks.
    required_absent_markers = [
        "USER_ABSENT",
        "HOME_ABSENT",
        "SUDO_MEMBERSHIP_ABSENT",
    ]

    # Count any expected absence marker that did not appear as a residual indicator.
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

    # Print the scenario's validation and residual metrics for later result recording.
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

    # Any remaining predefined local-user indicator blocks final acceptance.
    if residual_indicators != 0:
        print(
            "[FAIL] Unauthorized local-user persistence "
            "indicators remain after recovery."
        )
        return 1

    # After security-state validation, require monitoring readiness as the completion gate.
    (
        monitoring_restored,
        monitoring_restoration_duration,
    ) = wait_for_wazuh_restoration()

    if not monitoring_restored:
        return 1

    # Final PASS means all three local-user residual checks passed and monitoring was restored.
    print("[SUCCESS] Unauthorized local-user persistence is absent.")
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
