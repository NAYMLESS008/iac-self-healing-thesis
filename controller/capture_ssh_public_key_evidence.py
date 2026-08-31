from datetime import datetime, timezone
from pathlib import Path

from controller.iap_helpers import (
    run_target_command,
    run_wazuh_command,
)


# --- Scenario artefact, marker and evidence destination ---
AUTHORIZED_KEYS = "/home/thesisadmin/.ssh/authorized_keys"
ATTACK_MARKER = "THESIS_UNAUTHORIZED_SSH_KEY"
EVIDENCE_DIR = Path("evidence")


# --- Run one target-side evidence command and preserve its raw result ---
def target_section(title, command):
    result = run_target_command(command)

    section = (
        f"\n===== {title} =====\n"
        f"return_code: {result['return_code']}\n"
        f"stdout:\n{result['stdout']}\n"
        f"stderr:\n{result['stderr']}\n"
    )

    return result, section


# --- Capture all required SSH public-key evidence before replacement ---
def main():
    print(
        "[START] Capturing unauthorized SSH "
        "public-key persistence evidence"
    )

    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    evidence_file = (
        EVIDENCE_DIR
        / f"ssh_public_key_pre_replacement_{timestamp}.txt"
    )

    sections = []

    # 1. Record target identity and capture time/user.
    identity_result, section = target_section(
        "TARGET IDENTITY",
        "date --iso-8601=seconds; hostname; whoami",
    )
    sections.append(section)

    # 2. Preserve the exact unauthorized-key marker from authorized_keys.
    key_result, section = target_section(
        "UNAUTHORIZED KEY ENTRY",
        (
            f"if sudo grep -F '{ATTACK_MARKER}' "
            f"{AUTHORIZED_KEYS}; "
            "then echo ATTACK_MARKER_PRESENT; "
            "else echo ATTACK_MARKER_MISSING; fi"
        ),
    )
    sections.append(section)

    # 3-4. Capture file metadata and a SHA-256 fingerprint of its contents.
    stat_result, section = target_section(
        "AUTHORIZED_KEYS METADATA",
        f"sudo stat {AUTHORIZED_KEYS}",
    )
    sections.append(section)

    hash_result, section = target_section(
        "AUTHORIZED_KEYS SHA256",
        f"sudo sha256sum {AUTHORIZED_KEYS}",
    )
    sections.append(section)

    # 5. Record that the SSH service involved in the scenario is active.
    ssh_result, section = target_section(
        "SSH SERVICE STATUS",
        (
            "sudo systemctl is-active ssh "
            "|| sudo systemctl is-active sshd"
        ),
    )
    sections.append(section)

    # 6. Preserve the matching Wazuh FIM event for authorized_keys.
    wazuh_result = run_wazuh_command(
        "sudo grep -F "
        f"'{AUTHORIZED_KEYS}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| grep -F '\"location\":\"syscheck\"' "
        "| tail -n 1 || true"
    )

    sections.append(
        "\n===== WAZUH FIM ALERT =====\n"
        f"return_code: {wazuh_result['return_code']}\n"
        f"stdout:\n{wazuh_result['stdout']}\n"
        f"stderr:\n{wazuh_result['stderr']}\n"
    )

    # Save raw evidence before evaluating the checklist.
    evidence_file.write_text(
        (
            "UNAUTHORIZED SSH PUBLIC-KEY "
            "PERSISTENCE EVIDENCE\n"
            f"capture_timestamp_utc: "
            f"{datetime.now(timezone.utc).isoformat()}\n"
            f"authorized_keys: {AUTHORIZED_KEYS}\n"
            f"attack_marker: {ATTACK_MARKER}\n"
            + "".join(sections)
        ),
        encoding="utf-8",
    )

    # --- Six predefined evidence checklist items ---
    checks = {
        "target_identity": (
            identity_result["return_code"] == 0
            and "thesis-self-healing-vm"
            in identity_result["stdout"]
        ),
        "unauthorized_key_entry": (
            key_result["return_code"] == 0
            and "ATTACK_MARKER_PRESENT"
            in key_result["stdout"]
        ),
        "authorized_keys_metadata": (
            stat_result["return_code"] == 0
            and AUTHORIZED_KEYS in stat_result["stdout"]
        ),
        "authorized_keys_hash": (
            hash_result["return_code"] == 0
            and AUTHORIZED_KEYS in hash_result["stdout"]
        ),
        "ssh_service_status": (
            ssh_result["return_code"] == 0
            and "active" in ssh_result["stdout"]
        ),
        "wazuh_fim_alert": (
            wazuh_result["return_code"] == 0
            and AUTHORIZED_KEYS in wazuh_result["stdout"]
            and '"location":"syscheck"'
            in wazuh_result["stdout"]
        ),
    }

    required = len(checks)
    captured = sum(checks.values())
    percentage = round((captured / required) * 100, 2)

    print(
        f"[METRIC] evidence_items_required = {required}"
    )
    print(
        f"[METRIC] evidence_items_captured = {captured}"
    )
    print(
        "[METRIC] evidence_completeness_percentage = "
        f"{percentage}"
    )

    # Evidence is mandatory: any missing predefined item blocks later recovery.
    if captured != required:
        print(
            "[FAIL] SSH public-key evidence capture "
            "was incomplete."
        )
        print(f"[INFO] Evidence saved to: {evidence_file}")
        return 1

    print(f"[SUCCESS] Evidence captured: {evidence_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
