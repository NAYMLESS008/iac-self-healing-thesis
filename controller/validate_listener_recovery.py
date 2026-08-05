import json
import subprocess
import time
from pathlib import Path

try:
    from controller.iap_helpers import run_wazuh_command
except ModuleNotFoundError:
    from iap_helpers import run_wazuh_command


PROJECT_ROOT = Path(__file__).resolve().parents[1]
STATE_FILE = PROJECT_ROOT / "controller" / "ssh_rotation_state.json"

PROJECT_ID = "project-207ee30d-2273-45b0-8a0"
ZONE = "europe-west1-b"
TARGET_HOST = "thesis-self-healing-vm"
TARGET_USER = "thesisadmin"
TARGET_AGENT_NAME = "thesis-self-healing-vm"

PORT = 4444
PID_FILE = "/var/tmp/thesis-unexpected-listener.pid"
LOG_FILE = "/var/tmp/thesis-unexpected-listener.log"

WAZUH_MAX_ATTEMPTS = 60
WAZUH_WAIT_SECONDS = 15


def get_current_private_key():
    state = json.loads(
        STATE_FILE.read_text(encoding="utf-8-sig")
    )

    private_key = Path(state["new_private_key"])

    if not private_key.exists():
        raise FileNotFoundError(
            f"Current trusted key not found: {private_key}"
        )

    return private_key


def run_target_command(command):
    private_key = get_current_private_key()

    proxy_command = (
        "gcloud.cmd compute start-iap-tunnel "
        f"{TARGET_HOST} %p "
        "--listen-on-stdin "
        f"--zone={ZONE} "
        f"--project={PROJECT_ID}"
    )

    ssh_command = [
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
        f"{TARGET_USER}@{TARGET_HOST}",
        command,
    ]

    process = subprocess.Popen(
        ssh_command,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        encoding="utf-8",
        errors="replace",
        creationflags=subprocess.CREATE_NEW_PROCESS_GROUP,
    )

    try:
        stdout, stderr = process.communicate(timeout=30)
        return_code = process.returncode

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

        return_code = 0 if stdout.strip() else 124

    return {
        "return_code": return_code,
        "stdout": stdout.strip(),
        "stderr": stderr.strip(),
    }


def check_listener_artifacts():
    command = (
        f"if ss -H -lnt 'sport = :{PORT}' | grep -q .; "
        "then echo PORT_PRESENT; "
        "else echo PORT_ABSENT; fi; "

        "if ps -eo comm=,args= | "
        "awk '$1 == \"python3\" && "
        "$2 == \"python3\" && "
        "$3 == \"-m\" && "
        "$4 == \"http.server\" && "
        f"$5 == \"{PORT}\" "
        "{found=1} END {exit !found}'; "
        "then echo PROCESS_PRESENT; "
        "else echo PROCESS_ABSENT; fi; "

        f"if test -f {PID_FILE}; "
        "then echo PID_FILE_PRESENT; "
        "else echo PID_FILE_ABSENT; fi; "

        f"if test -f {LOG_FILE}; "
        "then echo LOG_FILE_PRESENT; "
        "else echo LOG_FILE_ABSENT; fi"
    )

    marker_groups = [
        ("PORT_ABSENT", "PORT_PRESENT"),
        ("PROCESS_ABSENT", "PROCESS_PRESENT"),
        ("PID_FILE_ABSENT", "PID_FILE_PRESENT"),
        ("LOG_FILE_ABSENT", "LOG_FILE_PRESENT"),
    ]

    last_result = {
        "return_code": 1,
        "stdout": "",
        "stderr": "",
    }

    for attempt in range(1, 4):
        last_result = run_target_command(command)
        output = last_result["stdout"]

        complete_output = all(
            any(marker in output for marker in group)
            for group in marker_groups
        )

        if complete_output:
            if attempt > 1:
                print(
                    "[SUCCESS] Listener validation output "
                    f"received on attempt {attempt}/3."
                )

            return last_result

        print(
            "[WARN] Listener validation output was incomplete "
            f"on attempt {attempt}/3; retrying."
        )

        if attempt < 3:
            time.sleep(5)

    return last_result


def wait_for_wazuh_restoration():
    print(
        "[CHECK] Waiting for Wazuh monitoring restoration..."
    )

    restoration_start = time.time()

    for attempt in range(
        1,
        WAZUH_MAX_ATTEMPTS + 1,
    ):
        target_result = run_target_command(
            "sudo systemctl is-active "
            "wazuh-agent || true"
        )

        target_status = target_result["stdout"].strip()

        fim_result = run_target_command(
            "sudo grep -Fq "
            "'Real-time file integrity monitoring started.' "
            "/var/ossec/logs/ossec.log "
            "&& echo FIM_READY || echo FIM_NOT_READY"
        )

        fim_ready = (
            "FIM_READY" in fim_result["stdout"]
            and "FIM_NOT_READY" not in fim_result["stdout"]
        )

        manager_result = run_wazuh_command(
            "sudo /var/ossec/bin/agent_control -l"
        )

        manager_active = (
            TARGET_AGENT_NAME in manager_result["stdout"]
            and "Active" in manager_result["stdout"]
        )

        print(
            f"[CHECK] Wazuh restoration attempt "
            f"{attempt}/{WAZUH_MAX_ATTEMPTS}: "
            f"local_status={target_status or 'UNKNOWN'}, "
            f"manager_active={manager_active}, "
            f"fim_realtime_ready={fim_ready}"
        )

        if (
            target_status == "active"
            and manager_active
            and fim_ready
        ):
            restoration_duration = round(
                time.time() - restoration_start,
                2,
            )

            print(
                "[SUCCESS] Wazuh agent is active locally."
            )
            print(
                "[SUCCESS] Replacement VM is active "
                "on Wazuh Manager."
            )
            print(
                "[SUCCESS] Real-time FIM monitoring is ready."
            )
            print("[METRIC] fim_realtime_ready = PASS")
            print(
                "[METRIC] "
                "monitoring_restoration_duration_seconds = "
                f"{restoration_duration}"
            )

            return True, restoration_duration

        if attempt < WAZUH_MAX_ATTEMPTS:
            time.sleep(WAZUH_WAIT_SECONDS)

    restoration_duration = round(
        time.time() - restoration_start,
        2,
    )

    print(
        "[FAIL] Wazuh monitoring and real-time FIM "
        "were not fully restored."
    )
    print("[METRIC] fim_realtime_ready = FAIL")
    print(
        "[METRIC] "
        "monitoring_restoration_duration_seconds = "
        f"{restoration_duration}"
    )

    return False, restoration_duration


def main():
    print(
        "[START] Validating unexpected-listener recovery"
    )

    result = check_listener_artifacts()

    if result["stdout"]:
        print(result["stdout"])

    if result["stderr"]:
        print("[STDERR]")
        print(result["stderr"])

    required_absent_markers = [
        "PORT_ABSENT",
        "PROCESS_ABSENT",
        "PID_FILE_ABSENT",
        "LOG_FILE_ABSENT",
    ]

    residual_indicators = sum(
        marker not in result["stdout"]
        for marker in required_absent_markers
    )

    total_indicators = len(
        required_absent_markers
    )

    validation_indicators_passed = (
        total_indicators - residual_indicators
    )

    validation_success_percentage = round(
        (
            validation_indicators_passed
            / total_indicators
        )
        * 100,
        2,
    )

    residual_score = (
        residual_indicators
        / total_indicators
    )

    print(
        "[METRIC] validation_indicators_total = "
        f"{total_indicators}"
    )
    print(
        "[METRIC] validation_indicators_passed = "
        f"{validation_indicators_passed}"
    )
    print(
        "[METRIC] validation_success_percentage = "
        f"{validation_success_percentage}"
    )
    print(
        "[METRIC] residual_compromise_count = "
        f"{residual_indicators}/{total_indicators}"
    )
    print(
        "[METRIC] residual_compromise_score = "
        f"{residual_score}"
    )

    if residual_indicators != 0:
        print(
            "[FAIL] Unexpected-listener indicators "
            "remain after recovery."
        )
        print("[METRIC] monitoring_restored = FAIL")
        print("[METRIC] fim_realtime_ready = NOT_RUN")
        return 1

    monitoring_restored, _ = (
        wait_for_wazuh_restoration()
    )

    if not monitoring_restored:
        print("[METRIC] monitoring_restored = FAIL")
        print("[RESULT] FAIL")
        return 1

    print(
        "[SUCCESS] Unexpected listener and its "
        "artifacts are absent."
    )
    print("[METRIC] monitoring_restored = PASS")
    print("[RESULT] PASS")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
