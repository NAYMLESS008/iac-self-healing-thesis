from datetime import datetime, timezone
from pathlib import Path

from controller.iap_helpers import run_target_command, run_wazuh_command


BACKDOOR_USER = "thesisbackdoor"
EVIDENCE_DIR = Path("evidence")


def run_target_section(title, command):
    result = run_target_command(command)

    section = (
        f"\n===== {title} =====\n"
        f"return_code: {result['return_code']}\n"
        f"stdout:\n{result['stdout']}\n"
        f"stderr:\n{result['stderr']}\n"
    )

    return result, section


def main():
    print("[START] Capturing unauthorized local-user evidence")

    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    evidence_file = (
        EVIDENCE_DIR
        / f"unauthorized_local_user_pre_replacement_{timestamp}.txt"
    )

    sections = []

    identity_result, section = run_target_section(
        "TARGET IDENTITY",
        "date --iso-8601=seconds; hostname"
    )
    sections.append(section)

    user_result, section = run_target_section(
        "USER ACCOUNT DETAILS",
        (
            f"if id {BACKDOOR_USER} >/dev/null 2>&1; "
            f"then id {BACKDOOR_USER}; "
            f"getent passwd {BACKDOOR_USER}; "
            "else echo USER_MISSING; fi"
        )
    )
    sections.append(section)

    group_result, section = run_target_section(
        "GROUP MEMBERSHIP",
        (
            f"if id {BACKDOOR_USER} >/dev/null 2>&1; "
            f"then id -nG {BACKDOOR_USER}; "
            "else echo USER_MISSING; fi"
        )
    )
    sections.append(section)

    home_result, section = run_target_section(
        "HOME DIRECTORY METADATA",
        (
            f"if test -d /home/{BACKDOOR_USER}; "
            f"then sudo stat /home/{BACKDOOR_USER}; "
            "else echo HOME_DIRECTORY_MISSING; fi"
        )
    )
    sections.append(section)

    passwd_result, section = run_target_section(
        "PASSWD ENTRY",
        f"sudo grep '^{BACKDOOR_USER}:' /etc/passwd || true"
    )
    sections.append(section)

    shadow_result, section = run_target_section(
        "SHADOW ENTRY",
        f"sudo grep '^{BACKDOOR_USER}:' /etc/shadow || true"
    )
    sections.append(section)

    sudo_result, section = run_target_section(
        "SUDO GROUP ENTRY",
        "getent group sudo"
    )
    sections.append(section)

    wazuh_result = run_wazuh_command(
        "sudo grep -F "
        f"'{BACKDOOR_USER}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 20 || true"
    )

    sections.append(
        "\n===== WAZUH ALERT EVIDENCE =====\n"
        f"return_code: {wazuh_result['return_code']}\n"
        f"stdout:\n{wazuh_result['stdout']}\n"
        f"stderr:\n{wazuh_result['stderr']}\n"
    )

    evidence_text = (
        "UNAUTHORIZED LOCAL-USER EVIDENCE\n"
        f"capture_timestamp_utc: "
        f"{datetime.now(timezone.utc).isoformat()}\n"
        f"backdoor_user: {BACKDOOR_USER}\n"
        + "".join(sections)
    )

    evidence_file.write_text(evidence_text, encoding="utf-8")

    identity_captured = (
        identity_result["return_code"] == 0
        and bool(identity_result["stdout"].strip())
    )

    user_captured = (
        user_result["return_code"] == 0
        and "USER_MISSING" not in user_result["stdout"]
        and BACKDOOR_USER in user_result["stdout"]
    )

    group_membership_captured = (
        group_result["return_code"] == 0
        and "USER_MISSING" not in group_result["stdout"]
        and "sudo" in group_result["stdout"].split()
    )

    home_metadata_captured = (
        home_result["return_code"] == 0
        and "HOME_DIRECTORY_MISSING" not in home_result["stdout"]
        and bool(home_result["stdout"].strip())
    )

    passwd_captured = (
        passwd_result["return_code"] == 0
        and f"{BACKDOOR_USER}:" in passwd_result["stdout"]
    )

    shadow_captured = (
        shadow_result["return_code"] == 0
        and f"{BACKDOOR_USER}:" in shadow_result["stdout"]
    )

    sudo_group_captured = (
        sudo_result["return_code"] == 0
        and BACKDOOR_USER in sudo_result["stdout"]
    )

    wazuh_captured = (
        wazuh_result["return_code"] == 0
        and '"id":"5902"' in wazuh_result["stdout"]
        and BACKDOOR_USER in wazuh_result["stdout"]
    )

    evidence_checks = {
        "target_identity": identity_captured,
        "user_account_details": user_captured,
        "group_membership": group_membership_captured,
        "home_directory_metadata": home_metadata_captured,
        "passwd_entry": passwd_captured,
        "shadow_entry": shadow_captured,
        "sudo_group_entry": sudo_group_captured,
        "wazuh_alert": wazuh_captured,
    }

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

    for item_name, captured in evidence_checks.items():
        status = "PASS" if captured else "FAIL"
        print(f"[EVIDENCE] {item_name} = {status}")

    if evidence_items_captured != evidence_items_required:
        print("[FAIL] Unauthorized-user evidence capture incomplete.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    print(f"[SUCCESS] Local-user evidence saved to: {evidence_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
