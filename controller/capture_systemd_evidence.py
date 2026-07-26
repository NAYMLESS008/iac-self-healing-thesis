import json
import subprocess
from datetime import datetime, timezone
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"


def get_current_private_key():
    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8")
    )

    private_key = Path(state["new_private_key"])

    if not private_key.exists():
        raise FileNotFoundError(
            f"Current trusted key not found: {private_key}"
        )

    return private_key


def run_remote_evidence_command(private_key):
    remote_command = r'''
echo "=== TIMESTAMP UTC ==="
date -u --iso-8601=seconds

echo
echo "=== HOST ==="
hostname
whoami

echo
echo "=== SERVICE FILE ==="
sudo ls -la /etc/systemd/system/thesis-persistence.service
sudo cat /etc/systemd/system/thesis-persistence.service

echo
echo "=== MALICIOUS SCRIPT ==="
sudo ls -la /usr/local/bin/thesis-persistence.sh
sudo cat /usr/local/bin/thesis-persistence.sh

echo
echo "=== SERVICE ENABLED STATE ==="
sudo systemctl is-enabled thesis-persistence.service || true

echo
echo "=== SERVICE ACTIVE STATE ==="
sudo systemctl is-active thesis-persistence.service || true

echo
echo "=== SERVICE STATUS ==="
sudo systemctl status thesis-persistence.service --no-pager || true

echo
echo "=== ENABLEMENT SYMLINK ==="
sudo ls -la /etc/systemd/system/multi-user.target.wants/thesis-persistence.service || true

echo
echo "=== RUNNING PROCESS ==="
sudo pgrep -a -f thesis-persistence || true

echo
echo "=== HEARTBEAT EVIDENCE ==="
sudo tail -n 10 /var/tmp/thesis-systemd-heartbeat.log || true

echo
echo "=== FILE HASHES ==="
sudo sha256sum \
  /etc/systemd/system/thesis-persistence.service \
  /usr/local/bin/thesis-persistence.sh || true
'''

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
        remote_command,
    ]

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
        stdout, stderr = process.communicate(timeout=45)
    except subprocess.TimeoutExpired as exc:
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""

        if isinstance(stdout, bytes):
            stdout = stdout.decode(errors="replace")

        if isinstance(stderr, bytes):
            stderr = stderr.decode(errors="replace")

        subprocess.run(
            [
                "taskkill",
                "/PID", str(process.pid),
                "/T",
                "/F",
            ],
            capture_output=True,
            text=True,
        )

    return stdout, stderr


def main():
    print(
        "[INFO] Capturing malicious systemd "
        "persistence evidence..."
    )

    private_key = get_current_private_key()
    stdout, stderr = run_remote_evidence_command(
        private_key
    )

    required_markers = [
        "thesis-persistence.service",
        "thesis-persistence.sh",
        "active",
        "enabled",
    ]

    if not all(
        marker in stdout
        for marker in required_markers
    ):
        print(stdout)

        if stderr:
            print(stderr)

        print(
            "[FAIL] Required systemd persistence "
            "evidence was not captured."
        )
        return 1

    EVIDENCE_DIR.mkdir(exist_ok=True)

    timestamp = datetime.now(
        timezone.utc
    ).strftime("%Y%m%d_%H%M%S")

    evidence_file = (
        EVIDENCE_DIR
        / (
            "systemd_persistence_pre_replacement_"
            f"{timestamp}.txt"
        )
    )

    content = (
        "MALICIOUS SYSTEMD PERSISTENCE EVIDENCE\n"
        "CAPTURED BEFORE TERRAFORM REPLACEMENT\n"
        "========================================\n\n"
        f"{stdout}\n"
    )

    if stderr:
        content += (
            "\n=== SSH/IAP STDERR ===\n"
            f"{stderr}\n"
        )

    evidence_file.write_text(
        content,
        encoding="utf-8",
    )

    print(
        f"[SUCCESS] Evidence captured: "
        f"{evidence_file}"
    )

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
