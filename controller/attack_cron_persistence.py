import base64
import json
import subprocess
import sys
from pathlib import Path


# Resolve project-relative files from the repository root.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
# The injector reuses the currently recorded rotated SSH private key for admin access.
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"

# Target VM and GCP connection details used by the controlled experiment.
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"
ZONE = "europe-west1-b"
PROJECT_ID = "project-207ee30d-2273-45b0-8a0"

# These are the two cron-scenario artefacts later checked by post-recovery validation.
CRON_FILE = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"


def get_current_private_key():
    # Fail early if the controller cannot locate its SSH-key rotation state.
    if not STATE_FILE.exists():
        raise FileNotFoundError(
            f"SSH rotation state not found: {STATE_FILE}"
        )

    # Read the saved state that identifies the currently valid private key.
    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8-sig")
    )

    private_key_value = state.get("new_private_key")

    if not private_key_value:
        raise ValueError(
            "new_private_key missing from SSH rotation state."
        )

    private_key = Path(private_key_value)

    # Do not attempt the attack if the referenced key file itself is missing.
    if not private_key.exists():
        raise FileNotFoundError(
            f"Current SSH private key not found: {private_key}"
        )

    return private_key


def main():
    private_key = get_current_private_key()

    # Build the shell script that is executed remotely on the controlled target VM.
    attack_script = rf'''set -e

CRON_FILE="{CRON_FILE}"
PAYLOAD_LOG="{PAYLOAD_LOG}"

# Refuse to create a duplicate compromise if the malicious cron file already exists.
if sudo test -f "$CRON_FILE"; then
    echo CRON_PERSISTENCE_ALREADY_PRESENT
    exit 1
fi

# A pre-existing payload log would make it unclear whether a new injection actually executed.
if sudo test -f "$PAYLOAD_LOG"; then
    echo STALE_PAYLOAD_LOG_PRESENT
    exit 1
fi

# Confirm the normal cron service is active before injecting the controlled scheduled task.
sudo systemctl is-active --quiet cron

# Listing 3 in the report: create a root-owned job that executes every minute.
# Its payload appends an explicit timestamped marker to /tmp/realtime-cron.log.
sudo tee "$CRON_FILE" >/dev/null <<'CRON_ATTACK'
* * * * * root /bin/sh -c 'echo "CRON_PERSISTENCE_ACTIVE $(date --iso-8601=seconds)" >> /tmp/realtime-cron.log'
CRON_ATTACK

# Set predictable ownership and permissions for the injected cron definition.
sudo chown root:root "$CRON_FILE"
sudo chmod 0644 "$CRON_FILE"

echo "[CHECK] Waiting for cron payload execution..."

payload_confirmed=0

# Poll for the payload marker so the experiment confirms execution, not just file creation.
for attempt in $(seq 1 18); do
    if sudo grep -q "CRON_PERSISTENCE_ACTIVE" "$PAYLOAD_LOG" 2>/dev/null; then
        payload_confirmed=1
        break
    fi

    echo "[CHECK] Payload attempt $attempt/18"
    sleep 5
done

# Abort the attack setup if cron never produced the expected execution marker.
if [ "$payload_confirmed" -ne 1 ]; then
    echo CRON_PAYLOAD_NOT_CONFIRMED
    exit 1
fi

# Print the created artefact and supporting execution evidence for visibility/audit output.
echo "=== CRON FILE ==="
sudo cat "$CRON_FILE"

echo "=== CRON FILE METADATA ==="
sudo stat "$CRON_FILE"

echo "=== PAYLOAD LOG ==="
sudo tail -n 5 "$PAYLOAD_LOG"

# Explicit success marker checked by the Python wrapper below.
echo MALICIOUS_CRON_PERSISTENCE_CREATED
'''

    # Base64 transport avoids shell-quoting problems when sending the multi-line script remotely.
    encoded = base64.b64encode(
        attack_script.encode("utf-8")
    ).decode("ascii")

    # Use Google Cloud IAP as the SSH transport path to the target VM.
    proxy_command = (
        "gcloud.cmd compute start-iap-tunnel "
        f"{TARGET_HOST} %p "
        "--listen-on-stdin "
        f"--zone={ZONE} "
        f"--project={PROJECT_ID}"
    )

    # Construct the non-interactive SSH command used to run the encoded attack script.
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

    # Start the SSH process and capture its stdout/stderr for confirmation and troubleshooting.
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
        # Allow enough time for the once-per-minute cron payload to execute and be confirmed.
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

        # Terminate the entire Windows process tree if the remote operation times out.
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

    # Only accept injection as successful when the remote script produced its explicit marker.
    if "MALICIOUS_CRON_PERSISTENCE_CREATED" not in stdout:
        print(
            "[ERROR] Malicious cron persistence was not confirmed."
        )
        sys.exit(1)

    print("[SUCCESS] Malicious cron persistence created.")


if __name__ == "__main__":
    main()