import time

from controller.iap_helpers import run_target_command, run_wazuh_command


MALICIOUS_CRON = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"
TARGET_AGENT_NAME = "thesis-self-healing-vm"

WAZUH_MAX_ATTEMPTS = 12
WAZUH_WAIT_SECONDS = 15


def check_cron_artifacts():
    command = (
        "echo === CRON FILE CHECK ===; "
        f"if test -f {MALICIOUS_CRON}; then echo CRON_PRESENT; "
        "else echo CRON_ABSENT; fi; "
        "echo === PAYLOAD LOG CHECK ===; "
        f"if test -f {PAYLOAD_LOG}; then echo PAYLOAD_LOG_PRESENT; "
        "else echo PAYLOAD_LOG_ABSENT; fi"
    )

    return run_target_command(command)


def wait_for_wazuh_restoration():
    print("[CHECK] Waiting for Wazuh monitoring restoration...")

    for attempt in range(1, WAZUH_MAX_ATTEMPTS + 1):
        target_result = run_target_command(
            "sudo systemctl is-active wazuh-agent || true"
        )

        target_status = target_result["stdout"].strip()

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
            f"manager_active={manager_active}"
        )

        if target_status == "active" and manager_active:
            print("[SUCCESS] Wazuh agent is active locally.")
            print("[SUCCESS] Replacement VM is active on Wazuh Manager.")
            return True

        if attempt < WAZUH_MAX_ATTEMPTS:
            time.sleep(WAZUH_WAIT_SECONDS)

    print("[FAIL] Wazuh monitoring was not fully restored within the wait window.")
    return False


def main():
    print("[START] Validating cron persistence recovery")

    result = check_cron_artifacts()

    if result["stdout"]:
        print(result["stdout"])

    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"])

    if result["return_code"] != 0:
        print("[FAIL] Could not complete cron artifact validation.")
        return 1

    stdout = result["stdout"]

    cron_absent = "CRON_ABSENT" in stdout
    payload_log_absent = "PAYLOAD_LOG_ABSENT" in stdout

    residual_indicators = 0

    if not cron_absent:
        residual_indicators += 1

    if not payload_log_absent:
        residual_indicators += 1

    total_indicators = 2
    residual_score = residual_indicators / total_indicators

    print(
        f"[METRIC] residual_compromise_count = "
        f"{residual_indicators}/{total_indicators}"
    )
    print(f"[METRIC] residual_compromise_score = {residual_score}")

    if residual_indicators != 0:
        print("[FAIL] Cron persistence indicators remain after recovery.")
        return 1

    monitoring_restored = wait_for_wazuh_restoration()

    if not monitoring_restored:
        return 1

    print("[SUCCESS] Malicious cron persistence is absent.")
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
