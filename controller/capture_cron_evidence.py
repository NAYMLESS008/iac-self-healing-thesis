from datetime import datetime, timezone
from pathlib import Path

from controller.iap_helpers import run_target_command, run_wazuh_command


# --- Scenario artefacts and local evidence destination ---
ATTACK_PATH = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"
EVIDENCE_DIR = Path("evidence")


# --- Run one target-side evidence command and format its raw result ---
def run_target_evidence_section(title, command):
    result = run_target_command(command)

    # Keep return code, stdout and stderr together so failed/partial collection
    # remains visible in the saved evidence file.
    section = (
        f"\n===== {title} =====\n"
        f"return_code: {result['return_code']}\n"
        f"stdout:\n{result['stdout']}\n"
        f"stderr:\n{result['stderr']}\n"
    )

    return result, section


# --- Capture all required cron evidence before destructive recovery ---
def main():
    print("[START] Capturing malicious cron persistence evidence")

    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    evidence_file = (
        EVIDENCE_DIR
        / f"cron_persistence_pre_replacement_{timestamp}.txt"
    )

    sections = []

    # 1. Identify exactly which target and time the evidence came from.
    identity_result, identity_section = run_target_evidence_section(
        "TARGET IDENTITY",
        "date --iso-8601=seconds; hostname"
    )
    sections.append(identity_section)

    # 2. Preserve the malicious cron definition itself.
    cron_result, cron_section = run_target_evidence_section(
        "MALICIOUS CRON FILE",
        (
            f"if test -f {ATTACK_PATH}; "
            f"then sudo cat {ATTACK_PATH}; "
            "else echo CRON_FILE_MISSING; fi"
        )
    )
    sections.append(cron_section)

    # 3. Preserve ownership, permissions, timestamps and other file metadata.
    stat_result, stat_section = run_target_evidence_section(
        "CRON FILE METADATA",
        (
            f"if test -f {ATTACK_PATH}; "
            f"then sudo stat {ATTACK_PATH}; "
            "else echo CRON_FILE_MISSING; fi"
        )
    )
    sections.append(stat_section)

    # 4. Capture proof that the scheduled payload actually executed.
    payload_result, payload_section = run_target_evidence_section(
        "PAYLOAD EXECUTION LOG",
        (
            f"if test -f {PAYLOAD_LOG}; "
            f"then sudo tail -n 50 {PAYLOAD_LOG}; "
            "else echo PAYLOAD_LOG_MISSING; fi"
        )
    )
    sections.append(payload_section)

    # 5. Record that the cron service responsible for scheduling is active.
    service_result, service_section = run_target_evidence_section(
        "CRON SERVICE STATUS",
        "sudo systemctl is-active cron"
    )
    sections.append(service_section)

    # 6. Preserve the matching Wazuh FIM alert from the trusted manager.
    wazuh_result = run_wazuh_command(
        "sudo grep -F "
        f"'{ATTACK_PATH}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| grep -F '\"location\":\"syscheck\"' "
        "| tail -n 1 || true"
    )

    wazuh_section = (
        "\n===== WAZUH ALERT EVIDENCE =====\n"
        f"return_code: {wazuh_result['return_code']}\n"
        f"stdout:\n{wazuh_result['stdout']}\n"
        f"stderr:\n{wazuh_result['stderr']}\n"
    )
    sections.append(wazuh_section)

    # Save all raw evidence sections before deciding whether the evidence gate passes.
    evidence_text = (
        "MALICIOUS CRON PERSISTENCE EVIDENCE\n"
        f"capture_timestamp_utc: "
        f"{datetime.now(timezone.utc).isoformat()}\n"
        f"attack_path: {ATTACK_PATH}\n"
        f"payload_log: {PAYLOAD_LOG}\n"
        + "".join(sections)
    )

    evidence_file.write_text(evidence_text, encoding="utf-8")

    # --- Convert raw collection results into the six required checklist items ---
    cron_captured = (
        cron_result["return_code"] == 0
        and "CRON_FILE_MISSING" not in cron_result["stdout"]
        and ATTACK_PATH not in cron_result["stderr"]
    )

    metadata_captured = (
        stat_result["return_code"] == 0
        and "CRON_FILE_MISSING" not in stat_result["stdout"]
    )

    payload_confirmed = (
        payload_result["return_code"] == 0
        and "CRON_PERSISTENCE_ACTIVE" in payload_result["stdout"]
    )

    wazuh_output = wazuh_result["stdout"]

    # Accept the relevant Wazuh file-added/changed rule IDs only when the exact
    # syscheck location and malicious path are also present.
    wazuh_captured = (
        wazuh_result["return_code"] == 0
        and (
            '"id":"550"' in wazuh_output
            or '"id":"554"' in wazuh_output
        )
        and '"location":"syscheck"' in wazuh_output
        and ATTACK_PATH in wazuh_output
    )

    identity_captured = identity_result["return_code"] == 0
    service_captured = service_result["stdout"].strip() == "active"

    evidence_checks = {
        "target_identity": identity_captured,
        "malicious_cron_file": cron_captured,
        "cron_file_metadata": metadata_captured,
        "payload_execution": payload_confirmed,
        "cron_service_status": service_captured,
        "wazuh_alert": wazuh_captured,
    }

    # Completeness is this scenario's predefined checklist score, not a claim
    # that every possible forensic artefact has been captured.
    evidence_items_required = len(evidence_checks)
    evidence_items_captured = sum(evidence_checks.values())

    evidence_completeness_percentage = round(
        (
            evidence_items_captured
            / evidence_items_required
        )
        * 100,
        2,
    )

    print(
        "[METRIC] evidence_items_required = "
        f"{evidence_items_required}"
    )
    print(
        "[METRIC] evidence_items_captured = "
        f"{evidence_items_captured}"
    )
    print(
        "[METRIC] evidence_completeness_percentage = "
        f"{evidence_completeness_percentage}"
    )

    # --- Evidence gate: every required item must be present before replacement ---
    if not cron_captured:
        print("[FAIL] Malicious cron file evidence was not captured.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    if not metadata_captured:
        print("[FAIL] Cron file metadata was not captured.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    if not payload_confirmed:
        print("[FAIL] Active cron payload execution was not confirmed.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    if not wazuh_captured:
        print("[FAIL] Matching Wazuh FIM evidence was not captured.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    if service_result["stdout"].strip() != "active":
        print("[FAIL] Cron service was not confirmed active.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    if identity_result["return_code"] != 0:
        print("[FAIL] Target identity evidence was not captured.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    print(f"[SUCCESS] Cron evidence saved to: {evidence_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
