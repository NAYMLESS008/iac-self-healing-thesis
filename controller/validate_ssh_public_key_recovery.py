import time

from controller.iap_helpers import (
    run_target_command,
    run_wazuh_command,
)


AUTHORIZED_KEYS = "/home/thesisadmin/.ssh/authorized_keys"
ATTACK_MARKER = "THESIS_UNAUTHORIZED_SSH_KEY"
TARGET_AGENT_NAME = "thesis-self-healing-vm"

WAZUH_MAX_ATTEMPTS = 60
WAZUH_WAIT_SECONDS = 15


def check_ssh_key_artifacts():
    command = (
        f"if sudo grep -Fq '{ATTACK_MARKER}' {AUTHORIZED_KEYS}; "
        "then echo UNAUTHORIZED_KEY_PRESENT; "
        "else echo UNAUTHORIZED_KEY_ABSENT; fi; "
        f"if sudo test -f {AUTHORIZED_KEYS}; "
        "then echo AUTHORIZED_KEYS_PRESENT; "
        "else echo AUTHORIZED_KEYS_MISSING; fi"
    )

    return run_target_command(command)


def wait_for_wazuh_restoration():
    print("[CHECK] Waiting for Wazuh monitoring restoration...")
    restoration_start = time.time()

    for attempt in range(1, WAZUH_MAX_ATTEMPTS + 1):
        local_result = run_target_command(
            "sudo systemctl is-active wazuh-agent || true"
        )

        local_status = local_result["stdout"].strip()

        manager_result = run_wazuh_command(
            "sudo /var/ossec/bin/agent_control -l"
        )

        manager_active = (
            TARGET_AGENT_NAME in manager_result["stdout"]
            and "Active" in manager_result["stdout"]
        )

        fim_result = run_target_command(
            "sudo sudo grep -Fq "
            "'Real-time file integrity monitoring started.' "
            "/var/ossec/logs/ossec.log "
            "&& echo FIM_READY || echo FIM_NOT_READY"
        )

        fim_ready = (
            "FIM_READY" in fim_result["stdout"]
            and "FIM_NOT_READY" not in fim_result["stdout"]
        )

        print(
            f"[CHECK] Wazuh restoration attempt "
            f"{attempt}/{WAZUH_MAX_ATTEMPTS}: "
            f"local_status={local_status or 'UNKNOWN'}, "
            f"manager_active={manager_active}, "
            f"fim_realtime_ready={fim_ready}"
        )

        if (
            local_status == "active"
            and manager_active
            and fim_ready
        ):
            duration = round(
                time.time() - restoration_start,
                2,
            )

            print("[SUCCESS] Wazuh agent is active locally.")
            print("[SUCCESS] Replacement VM is active on Wazuh Manager.")
            print("[SUCCESS] Real-time FIM monitoring is ready.")
            print("[METRIC] fim_realtime_ready = PASS")
            print(
                "[METRIC] monitoring_restoration_duration_seconds = "
                f"{duration}"
            )

            return True

        if attempt < WAZUH_MAX_ATTEMPTS:
            time.sleep(WAZUH_WAIT_SECONDS)

    duration = round(
        time.time() - restoration_start,
        2,
    )

    print("[FAIL] Wazuh monitoring restoration timed out.")
    print("[METRIC] fim_realtime_ready = FAIL")
    print(
        "[METRIC] monitoring_restoration_duration_seconds = "
        f"{duration}"
    )

    return False


def main():
    print(
        "[START] Validating unauthorized SSH "
        "public-key recovery"
    )

    result = check_ssh_key_artifacts()

    if result["stdout"]:
        print(result["stdout"])

    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"])

    if result["return_code"] != 0:
        print(
            "[FAIL] Could not complete SSH public-key "
            "artifact validation."
        )
        return 1

    stdout = result["stdout"]

    unauthorized_key_absent = (
        "UNAUTHORIZED_KEY_ABSENT" in stdout
    )
    authorized_keys_present = (
        "AUTHORIZED_KEYS_PRESENT" in stdout
    )

    residual_indicators = 0

    if not unauthorized_key_absent:
        residual_indicators += 1

    if not authorized_keys_present:
        residual_indicators += 1

    total_indicators = 2
    passed_indicators = (
        total_indicators - residual_indicators
    )

    percentage = round(
        (passed_indicators / total_indicators) * 100,
        2,
    )

    residual_score = (
        residual_indicators / total_indicators
    )

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
        f"{percentage}"
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
            "[FAIL] SSH public-key persistence indicators "
            "remain after recovery."
        )
        return 1

    if not wait_for_wazuh_restoration():
        return 1

    print(
        "[SUCCESS] Unauthorized SSH public-key "
        "persistence is absent."
    )
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())

