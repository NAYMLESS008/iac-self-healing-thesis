import csv
import json
import subprocess
from datetime import datetime
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"
EVIDENCE_DIR = PROJECT_ROOT / "evidence"
RESULTS_FILE = PROJECT_ROOT / "results" / "ssh_key_rotation_results.csv"

EXPECTED_USER = "thesisadmin"
EXPECTED_HOSTNAME = "thesis-self-healing-vm"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"


def load_rotation_state():
    if not STATE_FILE.exists():
        raise FileNotFoundError(
            f"Rotation state file not found: {STATE_FILE}"
        )

    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8")
    )

    required = [
        "compromised_private_key",
        "new_private_key",
        "new_public_key",
    ]

    for field in required:
        if not state.get(field):
            raise ValueError(
                f"Missing '{field}' in rotation state."
            )

    return state


def run_key_test(private_key):
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
        "-o", "ServerAliveInterval=5",
        "-o", "ServerAliveCountMax=2",
        "-o", "StrictHostKeyChecking=accept-new",
        "-i", str(private_key),
        "-o", f"ProxyCommand={proxy_command}",
        f"{EXPECTED_USER}@{TARGET_HOST}",
        "whoami && hostname",
    ]

    process = subprocess.Popen(
        command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    timed_out = False

    try:
        stdout, stderr = process.communicate(timeout=45)
        return_code = process.returncode
    except subprocess.TimeoutExpired as exc:
        timed_out = True

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

        try:
            remaining_stdout, remaining_stderr = (
                process.communicate(timeout=10)
            )
        except subprocess.TimeoutExpired:
            remaining_stdout = ""
            remaining_stderr = ""

        stdout += remaining_stdout or ""
        stderr += remaining_stderr or ""

        # Authentication result may already be complete even
        # though the Windows IAP proxy failed to terminate.
        if (
            EXPECTED_USER in stdout
            and EXPECTED_HOSTNAME in stdout
        ):
            return_code = 0
        elif (
            "Permission denied" in stderr
            or "publickey" in stderr
        ):
            return_code = 255
        else:
            return_code = 124

    return {
        "return_code": return_code,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
        "command": command,
        "iap_cleanup_timeout": timed_out,
    }


def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    readable_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    EVIDENCE_DIR.mkdir(exist_ok=True)
    RESULTS_FILE.parent.mkdir(exist_ok=True)

    try:
        state = load_rotation_state()
    except Exception as exc:
        print(f"[ERROR] {exc}")
        return 1

    new_private_key = Path(state["new_private_key"])
    compromised_private_key = Path(
        state["compromised_private_key"]
    )

    print("[INFO] Testing new trusted SSH key...")
    new_key_result = run_key_test(new_private_key)

    print("[INFO] Testing old compromised SSH key...")
    old_key_result = run_key_test(
        compromised_private_key
    )

    new_key_success = (
        new_key_result["return_code"] == 0
        and EXPECTED_USER in new_key_result["stdout"]
        and EXPECTED_HOSTNAME in new_key_result["stdout"]
    )

    old_key_denied = (
        old_key_result["return_code"] != 0
        and (
            "Permission denied" in old_key_result["stderr"]
            or "publickey" in old_key_result["stderr"]
        )
    )

    residual_compromise_count = (
        0 if old_key_denied else 1
    )
    residual_compromise_score = (
        0 if old_key_denied else 1
    )

    final_result = (
        "PASS"
        if new_key_success and old_key_denied
        else "FAIL"
    )

    evidence_file = (
        EVIDENCE_DIR
        / f"ssh_key_rotation_validation_{timestamp}.txt"
    )

    evidence_file.write_text(
        f"""SSH Key Rotation Validation Evidence

Date: {readable_time}

New trusted private key:
{new_private_key}

Old compromised private key:
{compromised_private_key}

=== NEW KEY TEST ===
Return code:
{new_key_result["return_code"]}

STDOUT:
{new_key_result["stdout"]}

STDERR:
{new_key_result["stderr"]}

=== OLD COMPROMISED KEY TEST ===
Return code:
{old_key_result["return_code"]}

STDOUT:
{old_key_result["stdout"]}

STDERR:
{old_key_result["stderr"]}

=== METRICS ===
new_key_success={new_key_success}
old_key_denied={old_key_denied}
residual_compromise_count={residual_compromise_count}/1
residual_compromise_score={residual_compromise_score}
final_result={final_result}
""",
        encoding="utf-8",
    )

    file_exists = RESULTS_FILE.exists()

    fieldnames = [
        "timestamp",
        "experiment",
        "new_private_key",
        "compromised_private_key",
        "new_key_success",
        "old_key_denied",
        "residual_compromise_count",
        "residual_compromise_score",
        "final_result",
        "evidence_file",
    ]

    with RESULTS_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as csv_file:
        writer = csv.DictWriter(
            csv_file,
            fieldnames=fieldnames,
        )

        if not file_exists:
            writer.writeheader()

        writer.writerow({
            "timestamp": readable_time,
            "experiment": "stolen_trusted_ssh_key",
            "new_private_key": str(new_private_key),
            "compromised_private_key": str(
                compromised_private_key
            ),
            "new_key_success": new_key_success,
            "old_key_denied": old_key_denied,
            "residual_compromise_count": (
                f"{residual_compromise_count}/1"
            ),
            "residual_compromise_score": (
                residual_compromise_score
            ),
            "final_result": final_result,
            "evidence_file": str(evidence_file),
        })

    print(
        f"[METRIC] new_key_success = "
        f"{new_key_success}"
    )
    print(
        f"[METRIC] old_key_denied = "
        f"{old_key_denied}"
    )
    print(
        f"[METRIC] residual_compromise_count = "
        f"{residual_compromise_count}/1"
    )
    print(
        f"[METRIC] residual_compromise_score = "
        f"{residual_compromise_score}"
    )
    print(f"[RESULT] {final_result}")
    print(f"[EVIDENCE] {evidence_file}")

    return 0 if final_result == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
