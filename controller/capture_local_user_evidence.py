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

    user_captured = (
        user_result["return_code"] == 0
        and "USER_MISSING" not in user_result["stdout"]
        and BACKDOOR_USER in user_result["stdout"]
    )

    sudo_membership_captured = (
        group_result["return_code"] == 0
        and "sudo" in group_result["stdout"].split()
    )

    passwd_captured = (
        passwd_result["return_code"] == 0
        and f"{BACKDOOR_USER}:" in passwd_result["stdout"]
    )

    shadow_captured = (
        shadow_result["return_code"] == 0
        and f"{BACKDOOR_USER}:" in shadow_result["stdout"]
    )

    wazuh_captured = (
        wazuh_result["return_code"] == 0
        and '"id":"5902"' in wazuh_result["stdout"]
        and BACKDOOR_USER in wazuh_result["stdout"]
    )

    if not all(
        [
            identity_result["return_code"] == 0,
            user_captured,
            sudo_membership_captured,
            passwd_captured,
            shadow_captured,
            wazuh_captured,
        ]
    ):
        print("[FAIL] Unauthorized-user evidence capture incomplete.")
        print(f"[INFO] Partial evidence saved to: {evidence_file}")
        return 1

    print(f"[SUCCESS] Local-user evidence saved to: {evidence_file}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
