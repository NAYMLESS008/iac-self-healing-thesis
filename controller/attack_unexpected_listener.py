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

PORT = 4444


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

PID_FILE=/var/tmp/thesis-unexpected-listener.pid
LOG_FILE=/var/tmp/thesis-unexpected-listener.log

if ss -H -lnt 'sport = :{PORT}' | grep -q .; then
    echo LISTENER_ALREADY_PRESENT
    exit 1
fi

nohup python3 -m http.server {PORT} \
    --bind 0.0.0.0 \
    >"$LOG_FILE" 2>&1 </dev/null &

listener_pid=$!
echo "$listener_pid" > "$PID_FILE"

sleep 2

kill -0 "$listener_pid"
ss -H -lntp 'sport = :{PORT}'

echo "PID=$listener_pid"
echo UNEXPECTED_LISTENER_CREATED
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
        "-o", "BatchMode=yes",
        "-o", "IdentitiesOnly=yes",
        "-o", "ConnectTimeout=15",
        "-o", "ConnectionAttempts=1",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", str(private_key),
        "-o", f"ProxyCommand={proxy_command}",
        f"{TARGET_USER}@{TARGET_HOST}",
        f"echo {encoded} | base64 -d | bash",
    ]

    print(
        f"[INFO] Creating unexpected TCP listener on port {PORT}..."
    )

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
        stdout, stderr = process.communicate(timeout=60)

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

    if "UNEXPECTED_LISTENER_CREATED" not in stdout:
        print(
            "[ERROR] Unexpected listener was not confirmed."
        )
        sys.exit(1)

    print("[SUCCESS] Unexpected listener created.")


if __name__ == "__main__":
    main()