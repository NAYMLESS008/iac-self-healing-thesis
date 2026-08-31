import time

from controller.iap_helpers import run_target_command, run_wazuh_command


# Attack-specific artefacts that must be absent after replacement.
MALICIOUS_CRON = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"
# Expected Wazuh agent name for manager-side restoration checks.
TARGET_AGENT_NAME = "thesis-self-healing-vm"

# Polling window for monitoring restoration: up to 60 attempts, 15 seconds apart.
WAZUH_MAX_ATTEMPTS = 60
WAZUH_WAIT_SECONDS = 15


def check_cron_artifacts():
    # Listing 4 in the report: perform explicit positive/negative checks for both
    # cron-scenario artefacts. The validator expects CRON_ABSENT and PAYLOAD_LOG_ABSENT.
    command = (
        "echo === CRON FILE CHECK ===; "
        f"if test -f {MALICIOUS_CRON}; then echo CRON_PRESENT; "
        "else echo CRON_ABSENT; fi; "
        "echo === PAYLOAD LOG CHECK ===; "
        f"if test -f {PAYLOAD_LOG}; then echo PAYLOAD_LOG_PRESENT; "
        "else echo PAYLOAD_LOG_ABSENT; fi"
    )

    # Run the checks on the replacement target through the controller's admin helper.
    return run_target_command(command)


def wait_for_wazuh_restoration():
    # Recovery is not accepted just because the malicious cron artefacts are gone.
    # The replacement must also return to the study's required observable monitoring state.
    print("[CHECK] Waiting for Wazuh monitoring restoration...")
    restoration_start = time.time()

    for attempt in range(1, WAZUH_MAX_ATTEMPTS + 1):
        # Check 1: local wazuh-agent systemd service must be active on the replacement VM.
        target_result = run_target_command(
            "sudo systemctl is-active wazuh-agent || true"
        )

        target_status = target_result["stdout"].strip()

        # Check 2: look for the study-specific marker showing real-time FIM startup completed.
        fim_result = run_target_command(
            "sudo grep -Fq "
            "'Real-time file integrity monitoring started.' "
            "/var/ossec/logs/ossec.log "
            "&& echo FIM_READY || echo FIM_NOT_READY"
        )

        # Require the explicit ready marker and reject the explicit not-ready marker.
        fim_ready = (
            "FIM_READY" in fim_result["stdout"]
            and "FIM_NOT_READY" not in fim_result["stdout"]
        )

        # Check 3: the trusted Wazuh Manager must list the replacement agent as Active.
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

        # Monitoring restoration passes only when all three readiness conditions are true.
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
            print("[SUCCESS] Replacement VM is active on Wazuh Manager.")
            print("[SUCCESS] Real-time FIM monitoring is ready.")
            print("[METRIC] fim_realtime_ready = PASS")
            print(
                "[METRIC] monitoring_restoration_duration_seconds = "
                f"{restoration_duration}"
            )
            return True, restoration_duration

        # Give the replacement monitoring stack time to finish startup before checking again.
        if attempt < WAZUH_MAX_ATTEMPTS:
            time.sleep(WAZUH_WAIT_SECONDS)

    # If the polling window ends, record how long was spent waiting and fail validation.
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
    print("[START] Validating cron persistence recovery")

    # First validate the attack-specific security state on the replacement VM.
    result = check_cron_artifacts()

    if result["stdout"]:
        print(result["stdout"])

    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"])

    # Transport/command failure is not interpreted as proof that an artefact is absent.
    if result["return_code"] != 0:
        print("[FAIL] Could not complete cron artifact validation.")
        return 1

    stdout = result["stdout"]

    # Each explicit ABSENT marker represents one passed post-recovery condition.
    cron_absent = "CRON_ABSENT" in stdout
    payload_log_absent = "PAYLOAD_LOG_ABSENT" in stdout

    # Count predefined indicators that did not pass their required absence check.
    residual_indicators = 0

    if not cron_absent:
        residual_indicators += 1

    if not payload_log_absent:
        residual_indicators += 1

    # Cron has exactly two predefined post-recovery indicators in this experiment.
    total_indicators = 2
    passed_indicators = total_indicators - residual_indicators
    validation_success_percentage = round(
        (passed_indicators / total_indicators) * 100,
        2,
    )
    residual_score = residual_indicators / total_indicators

    # Emit the values later recorded/analysed as validation metrics.
    print(
        "[METRIC] validation_indicators_total = "
        f"{total_indicators}"
    )
    print(
        "[METRIC] validation_indicators_passed = "
        f"{passed_indicators}"
    )
    print(
        "[METRIC] validation_success_percentage = "
        f"{validation_success_percentage}"
    )
    print(
        f"[METRIC] residual_compromise_count = "
        f"{residual_indicators}/{total_indicators}"
    )
    print(f"[METRIC] residual_compromise_score = {residual_score}")

    # Any predefined cron residual blocks recovery acceptance.
    if residual_indicators != 0:
        print("[FAIL] Cron persistence indicators remain after recovery.")
        return 1

    # Only after attack-specific indicators pass do we wait for monitoring readiness.
    (
        monitoring_restored,
        monitoring_restoration_duration,
    ) = wait_for_wazuh_restoration()

    if not monitoring_restored:
        return 1

    # Final PASS therefore means: cron indicators absent + required monitoring state restored.
    print("[SUCCESS] Malicious cron persistence is absent.")
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
