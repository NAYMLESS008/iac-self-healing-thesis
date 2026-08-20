import subprocess
from datetime import datetime
from pathlib import Path

from controller.iap_helpers import run_target_command, run_wazuh_command


EVIDENCE_DIR = Path("evidence")
TARGET_AUTHORIZED_KEYS = "/home/thesisadmin/.ssh/authorized_keys"


def run_old_key_test():
    result = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "ConnectTimeout=10",
            "thesis-target-old-compromised-key",
            "whoami && hostname"
        ],
        capture_output=True,
        text=True
    )

    return result


def main():
    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    evidence_file = EVIDENCE_DIR / f"stolen_trusted_ssh_key_pre_replacement_{timestamp}.txt"

    print("[INFO] Capturing stolen trusted SSH-key evidence...")

    target_command = f"""
echo '=== TARGET SYSTEM INFO ==='
hostname
date -u

echo ''
echo '=== AUTHORIZED_KEYS STAT ==='
stat {TARGET_AUTHORIZED_KEYS}

echo ''
echo '=== AUTHORIZED_KEYS CONTENT ==='
cat {TARGET_AUTHORIZED_KEYS}
"""

    target_result = run_target_command(target_command)

    wazuh_result = run_wazuh_command(
        "sudo grep -i authorized_keys /var/ossec/logs/alerts/alerts.json | tail -n 5"
    )

    old_key_result = run_old_key_test()

    with evidence_file.open("w", encoding="utf-8") as f:
        f.write("STOLEN TRUSTED SSH KEY EVIDENCE - PRE REPLACEMENT\n")
        f.write("=" * 60 + "\n")
        f.write(f"Captured at: {datetime.now()}\n\n")

        f.write("=== TARGET AUTHORIZED_KEYS EVIDENCE ===\n")
        f.write(target_result.get("stdout", ""))
        f.write("\nSTDERR:\n")
        f.write(target_result.get("stderr", ""))

        f.write("\n\n=== WAZUH ALERT EVIDENCE ===\n")
        f.write(wazuh_result.get("stdout", ""))
        f.write("\nSTDERR:\n")
        f.write(wazuh_result.get("stderr", ""))

        f.write("\n\n=== OLD COMPROMISED KEY ACCESS TEST ===\n")
        f.write(f"Return code: {old_key_result.returncode}\n")
        f.write("STDOUT:\n")
        f.write(old_key_result.stdout)
        f.write("\nSTDERR:\n")
        f.write(old_key_result.stderr)

    print(f"[SUCCESS] Evidence captured: {evidence_file}")


if __name__ == "__main__":
    main()
