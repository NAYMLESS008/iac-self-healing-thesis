import json
import subprocess
import time
from pathlib import Path

from controller.alert_state import (
    is_alert_processed,
    save_selected_alert,
)
from controller.iap_helpers import run_wazuh_command


TARGET_AGENT_NAME = "thesis-self-healing-vm"
ALERTS_FILE = "/var/ossec/logs/alerts/alerts.json"

SCENARIO = "stolen_trusted_ssh_key"
COMPROMISED_RULE_ID = "100002"
PROJECT_ROOT = Path(__file__).resolve().parents[1]
ROTATION_STATE_FILE = (
    PROJECT_ROOT / "controller" / "ssh_rotation_state.json"
)


def get_compromised_fingerprint():
    """
    Calculate the fingerprint of the SSH key currently trusted
    before the recovery workflow rotates it.
    """
    if not ROTATION_STATE_FILE.exists():
        raise FileNotFoundError(
            f"Rotation state not found: {ROTATION_STATE_FILE}"
        )

    try:
        state = json.loads(
            ROTATION_STATE_FILE.read_text(encoding="utf-8")
        )
    except json.JSONDecodeError as exc:
        raise RuntimeError(
            f"Invalid rotation state JSON: "
            f"{ROTATION_STATE_FILE}"
        ) from exc

    public_key_value = state.get("new_public_key")

    if not public_key_value:
        raise KeyError(
            "new_public_key is missing from rotation state."
        )

    public_key = Path(public_key_value)

    if not public_key.exists():
        raise FileNotFoundError(
            f"Current trusted public key not found: "
            f"{public_key}"
        )

    result = subprocess.run(
        [
            "ssh-keygen",
            "-lf",
            str(public_key),
        ],
        capture_output=True,
        text=True,
        timeout=15,
    )

    if result.returncode != 0:
        raise RuntimeError(
            "Could not calculate current trusted key "
            f"fingerprint: {result.stderr.strip()}"
        )

    parts = result.stdout.strip().split()

    fingerprint = next(
        (
            part
            for part in parts
            if part.startswith("SHA256:")
        ),
        None,
    )

    if not fingerprint:
        raise RuntimeError(
            "ssh-keygen output did not contain a "
            "SHA256 fingerprint."
        )

    return fingerprint


COMPROMISED_FINGERPRINT = get_compromised_fingerprint()

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"

EXPECTED_USER = "thesisadmin"
EXPECTED_HOSTNAME = "thesis-self-healing-vm"


def get_compromised_private_key():
    if not ROTATION_STATE_FILE.exists():
        raise FileNotFoundError(
            f"Rotation state not found: {ROTATION_STATE_FILE}"
        )

    state = json.loads(
        ROTATION_STATE_FILE.read_text(encoding="utf-8")
    )

    # Before the next rotation, the previous run's new key is
    # the currently trusted key now considered compromised.
    key_path = state.get("new_private_key")

    if not key_path:
        raise ValueError(
            "new_private_key is missing from rotation state."
        )

    private_key = Path(key_path)

    if not private_key.exists():
        raise FileNotFoundError(
            f"Compromised private key not found: {private_key}"
        )

    return private_key


def compromised_key_is_active():
    try:
        compromised_private_key = (
            get_compromised_private_key()
        )
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return False

    proxy_command = (
        "gcloud.cmd compute start-iap-tunnel "
        f"{TARGET_HOST} %p "
        "--listen-on-stdin "
        f"--zone={ZONE} "
        f"--project={PROJECT_ID}"
    )

    result = subprocess.run(
        [
            "ssh",
            "-o", "BatchMode=yes",
            "-o", "IdentitiesOnly=yes",
            "-o", "ConnectTimeout=15",
            "-o", "StrictHostKeyChecking=accept-new",
            "-i", str(compromised_private_key),
            "-o", f"ProxyCommand={proxy_command}",
            f"{EXPECTED_USER}@{TARGET_HOST}",
            "whoami && hostname",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )

    if result.stdout:
        print(result.stdout.strip())

    if result.stderr:
        print(result.stderr.strip())

    return (
        result.returncode == 0
        and EXPECTED_USER in result.stdout
        and EXPECTED_HOSTNAME in result.stdout
    )


def get_matching_alerts():
    command = (
        f"sudo tail -n 500 {ALERTS_FILE} "
        f"| grep -F '\"id\":\"{COMPROMISED_RULE_ID}\"' "
        "|| true"
    )

    result = None

    for attempt in range(1, 4):
        result = run_wazuh_command(command)

        if result["success"]:
            break

        print(
            f"[WARN] Wazuh alert read attempt "
            f"{attempt}/3 failed."
        )

        if result["stderr"].strip():
            print(result["stderr"].strip())

        if attempt < 3:
            time.sleep(5)

    if not result or not result["success"]:
        print("[ERROR] Could not read Wazuh alerts.")
        return []

    matching_alerts = []

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        rule_id = str(
            alert.get("rule", {}).get("id", "")
        )

        agent_name = alert.get(
            "agent", {}
        ).get("name")

        location = alert.get("location", "")
        full_log = alert.get("full_log", "")
        alert_id = str(alert.get("id", ""))

        if (
            alert_id
            and rule_id == COMPROMISED_RULE_ID
            and agent_name == TARGET_AGENT_NAME
            and location == "/var/log/auth.log"
            and COMPROMISED_FINGERPRINT in full_log
        ):
            matching_alerts.append(alert)

    return matching_alerts


def unprocessed_compromised_key_alert_exists():
    matching_alerts = get_matching_alerts()

    if not matching_alerts:
        print(
            "[RESULT] No matching compromised-key "
            "authentication alert found."
        )
        return False

    latest_alert = matching_alerts[-1]
    alert_id = str(latest_alert["id"])

    if is_alert_processed(SCENARIO, alert_id):
        print(
            f"[ALREADY PROCESSED] Alert {alert_id} "
            "has already completed recovery."
        )
        return False

    save_selected_alert(SCENARIO, alert_id)

    print("[UNPROCESSED COMPROMISED-KEY ALERT FOUND]")
    print(f"[ALERT ID] {alert_id}")
    print(
        "[RULE]",
        latest_alert.get("rule", {}).get("id"),
        "-",
        latest_alert.get("rule", {}).get(
            "description"
        ),
    )
    print(
        "[FINGERPRINT]",
        COMPROMISED_FINGERPRINT
    )
    print(json.dumps(latest_alert))

    return True


def main():
    print(
        "[INFO] Checking Wazuh for use of the "
        "known compromised SSH key..."
    )

    if not unprocessed_compromised_key_alert_exists():
        return 1

    if compromised_key_is_active():
        print(
            "[CONFIRMED] The compromised trusted "
            "private key still authenticates."
        )
        return 0

    print(
        "[RESULT] Wazuh detected compromised-key use, "
        "but the key no longer authenticates."
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())


