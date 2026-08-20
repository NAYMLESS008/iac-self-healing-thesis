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

CRON_FILE = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"


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

    attack_script = rf'''set -e

CRON_FILE="{CRON_FILE}"
PAYLOAD_LOG="{PAYLOAD_LOG}"

if sudo test -f "$CRON_FILE"; then
    echo CRON_PERSISTENCE_ALREADY_PRESENT
    exit 1
fi

if sudo test -f "$PAYLOAD_LOG"; then
    echo STALE_PAYLOAD_LOG_PRESENT
    exit 1
fi

sudo systemctl is-active --quiet cron

sudo tee "$CRON_FILE" >/dev/null <<'CRON_ATTACK'
* * * * * root /bin/sh -c 'echo "CRON_PERSISTENCE_ACTIVE $(date --iso-8601=seconds)" >> /tmp/realtime-cron.log'
CRON_ATTACK

sudo chown root:root "$CRON_FILE"
sudo chmod 0644 "$CRON_FILE"

echo "[CHECK] Waiting for cron payload execution..."

payload_confirmed=0

for attempt in $(seq 1 18); do
    if sudo grep -q "CRON_PERSISTENCE_ACTIVE" "$PAYLOAD_LOG" 2>/dev/null; then
        payload_confirmed=1
        break
    fi

    echo "[CHECK] Payload attempt $attempt/18"
    sleep 5
done

if [ "$payload_confirmed" -ne 1 ]; then
    echo CRON_PAYLOAD_NOT_CONFIRMED
    exit 1
fi

echo "=== CRON FILE ==="
sudo cat "$CRON_FILE"

echo "=== CRON FILE METADATA ==="
sudo stat "$CRON_FILE"

echo "=== PAYLOAD LOG ==="
sudo tail -n 5 "$PAYLOAD_LOG"

echo MALICIOUS_CRON_PERSISTENCE_CREATED
'''

    encoded = base64.b64encode(
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
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-i",
        str(private_key),
        "-o",
        f"ProxyCommand={proxy_command}",
        f"{TARGET_USER}@{TARGET_HOST}",
        f"echo {encoded} | base64 -d | bash",
    ]

    print("[INFO] Creating malicious cron persistence...")

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    try:
        stdout, stderr = process.communicate(timeout=150)

    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(
                "utf-8",
                errors="replace",
            )

        if isinstance(stderr, bytes):
            stderr = stderr.decode(
                "utf-8",
                errors="replace",
            )

        subprocess.run(
            [
                "taskkill",
                "/PID",
                str(process.pid),
                "/T",
                "/F",
            ],
            capture_output=True,
            text=True,
        )

    if stdout:
        print(stdout.strip())

    if stderr:
        print(stderr.strip())

    if "MALICIOUS_CRON_PERSISTENCE_CREATED" not in stdout:
        print(
            "[ERROR] Malicious cron persistence was not confirmed."
        )
        sys.exit(1)

    print("[SUCCESS] Malicious cron persistence created.")


if __name__ == "__main__":
    main()