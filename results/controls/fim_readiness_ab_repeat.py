import csv
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Allow this control script to import the thesis controller package
PROJECT_ROOT = Path(__file__).resolve().parents[2]

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from controller.alert_state import (
    mark_selected_alert_processed,
    save_selected_alert,
)
from controller.iap_helpers import (
    run_target_command,
    run_wazuh_command,
)


SCENARIO = "malicious_cron_persistence"
ATTACK_PATH = "/etc/cron.d/realtime_evil_persistence"
PAYLOAD_LOG = "/tmp/realtime-cron.log"
TARGET_AGENT_NAME = "thesis-self-healing-vm"

RESULT_FILE = Path(
    "results/controls/fim_readiness_cron_ab_reps_2_3.csv"
)


def clean():
    run_target_command(
        f"sudo rm -f {ATTACK_PATH} {PAYLOAD_LOG}"
    )
    print("[CLEAN] Cron artifacts removed.")


def get_status_and_marker_count():
    result = run_target_command(
        "status=$(sudo systemctl is-active wazuh-agent "
        "2>/dev/null || true); "
        "count=$(sudo grep -Fc "
        "'Real-time file integrity monitoring started.' "
        "/var/ossec/logs/ossec.log 2>/dev/null || true); "
        'echo "STATUS=$status"; '
        'echo "COUNT=$count"'
    )

    status = "UNKNOWN"
    count = -1

    for line in result["stdout"].splitlines():
        if line.startswith("STATUS="):
            status = line.split("=", 1)[1].strip()

        if line.startswith("COUNT="):
            try:
                count = int(
                    line.split("=", 1)[1].strip()
                )
            except ValueError:
                count = -1

    return status, count


def get_artifact_mtime():
    result = run_target_command(
        f"date -r {ATTACK_PATH} +%s.%N"
    )

    try:
        return float(result["stdout"].strip())
    except ValueError:
        return None


def run_attack():
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "controller.attack_cron_persistence",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print("[ATTACK STDERR]")
        print(result.stderr)

    print(f"[ATTACK EXIT] {result.returncode}")

    return result.returncode


def latest_matching_alert():
    result = run_wazuh_command(
        "sudo grep -F "
        f"'{ATTACK_PATH}' "
        "/var/ossec/logs/alerts/alerts.json "
        "| tail -n 200 || true"
    )

    alerts = []

    for line in result["stdout"].splitlines():
        try:
            alert = json.loads(line)
        except json.JSONDecodeError:
            continue

        alert_id = str(alert.get("id", ""))
        agent = alert.get("agent", {}).get("name")
        syscheck = alert.get("syscheck", {})
        path = syscheck.get("path")
        event = syscheck.get("event")
        groups = alert.get("rule", {}).get(
            "groups",
            [],
        )

        if (
            alert_id
            and agent == TARGET_AGENT_NAME
            and path == ATTACK_PATH
            and event in {"added", "modified"}
            and "syscheck" in groups
        ):
            alerts.append(alert)

    if not alerts:
        return None

    return alerts[-1]


def wait_for_new_alert(old_id, timeout_seconds=180):
    start = time.time()

    while time.time() - start < timeout_seconds:
        alert = latest_matching_alert()

        if alert is not None:
            alert_id = str(alert.get("id", ""))

            if alert_id and alert_id != old_id:
                return alert

        print("[WAIT] Waiting for new Wazuh alert...")
        time.sleep(10)

    return None


def alert_epoch(alert):
    if not alert:
        return None

    value = alert.get("timestamp")

    if not value:
        return None

    try:
        parsed = datetime.strptime(
            value,
            "%Y-%m-%dT%H:%M:%S.%f%z",
        )
        return parsed.timestamp()

    except ValueError:
        return None


def process_control_alert(alert):
    if not alert:
        return

    alert_id = str(alert["id"])

    save_selected_alert(
        SCENARIO,
        alert_id,
    )

    ok = mark_selected_alert_processed(
        SCENARIO
    )

    print(
        f"[STATE] Control alert {alert_id}: "
        f"{'PROCESSED' if ok else 'STATE UPDATE FAILED'}"
    )


def save_row(row):
    RESULT_FILE.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    exists = RESULT_FILE.exists()

    with RESULT_FILE.open(
        "a",
        newline="",
        encoding="utf-8",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=list(row.keys()),
        )

        if not exists:
            writer.writeheader()

        writer.writerow(row)


def run_pair(rep):
    print("\n")
    print("=" * 60)
    print(f" FIM READINESS A/B REPETITION {rep}")
    print("=" * 60)

    clean()

    # --------------------------------------------------
    # CONDITION A
    # --------------------------------------------------

    print("\n=== CONDITION A: ACTIVE / FIM NOT READY ===")

    previous_alert = latest_matching_alert()
    previous_id = (
        str(previous_alert["id"])
        if previous_alert
        else ""
    )

    _, before_count = get_status_and_marker_count()

    print(f"FIM_MARKERS_BEFORE={before_count}")

    restart_start = time.monotonic()

    run_target_command(
        "sudo systemctl restart wazuh-agent"
    )

    active_seconds = None

    while True:
        status, count = get_status_and_marker_count()

        elapsed = round(
            time.monotonic() - restart_start,
            2,
        )

        print(
            f"ELAPSED={elapsed}s "
            f"AGENT={status} "
            f"FIM_MARKERS={count}"
        )

        if status == "active":
            active_seconds = elapsed
            break

        time.sleep(3)

    if count > before_count:
        print(
            "[INVALID] FIM became ready before "
            "Condition A attack."
        )

        clean()

        return {
            "repetition": rep,
            "result": "INVALID_PRE_READY_WINDOW",
        }

    print("PRE_READY_WINDOW_CONFIRMED=YES")

    if run_attack() != 0:
        clean()

        return {
            "repetition": rep,
            "result": "ATTACK_A_FAILED",
        }

    attack_a_epoch = get_artifact_mtime()

    _, count_after_attack = get_status_and_marker_count()

    attack_a_before_ready = (
        count_after_attack == before_count
    )

    print(
        "ATTACK_A_COMPLETED_BEFORE_FIM_READY="
        f"{'YES' if attack_a_before_ready else 'NO'}"
    )

    print("[WAIT] Waiting for fresh FIM readiness...")

    fim_ready_seconds = None

    while True:
        _, current_count = get_status_and_marker_count()

        elapsed = round(
            time.monotonic() - restart_start,
            2,
        )

        if current_count > before_count:
            fim_ready_seconds = elapsed
            break

        print(
            f"WAITING_FOR_FIM elapsed={elapsed}s"
        )

        time.sleep(10)

    print(
        f"NEW_FIM_READY_SECONDS={fim_ready_seconds}"
    )

    gap = round(
        fim_ready_seconds - active_seconds,
        2,
    )

    print(
        f"ACTIVE_TO_FIM_READY_GAP_SECONDS={gap}"
    )

    alert_a = wait_for_new_alert(
        previous_id
    )

    alert_a_epoch = alert_epoch(alert_a)

    delay_a = None

    if (
        alert_a_epoch is not None
        and attack_a_epoch is not None
    ):
        delay_a = round(
            alert_a_epoch - attack_a_epoch,
            3,
        )

    print(
        "CONDITION_A_ALERT="
        f"{'YES' if alert_a else 'NO'}"
    )

    print(
        f"CONDITION_A_ALERT_DELAY_SECONDS={delay_a}"
    )

    process_control_alert(alert_a)

    # --------------------------------------------------
    # CONDITION B
    # --------------------------------------------------

    print("\n=== CONDITION B: FIM READY ===")

    clean()
    time.sleep(5)

    previous_alert = latest_matching_alert()
    previous_id = (
        str(previous_alert["id"])
        if previous_alert
        else ""
    )

    status, ready_count = get_status_and_marker_count()

    print(f"AGENT_STATUS={status}")
    print(f"FIM_MARKERS_READY={ready_count}")

    if run_attack() != 0:
        clean()

        return {
            "repetition": rep,
            "result": "ATTACK_B_FAILED",
        }

    attack_b_epoch = get_artifact_mtime()

    alert_b = wait_for_new_alert(
        previous_id
    )

    alert_b_epoch = alert_epoch(alert_b)

    delay_b = None

    if (
        alert_b_epoch is not None
        and attack_b_epoch is not None
    ):
        delay_b = round(
            alert_b_epoch - attack_b_epoch,
            3,
        )

    print(
        "CONDITION_B_ALERT="
        f"{'YES' if alert_b else 'NO'}"
    )

    print(
        f"CONDITION_B_ALERT_DELAY_SECONDS={delay_b}"
    )

    process_control_alert(alert_b)

    clean()

    row = {
        "repetition": rep,
        "agent_active_seconds": active_seconds,
        "fim_ready_seconds": fim_ready_seconds,
        "active_to_fim_ready_gap_seconds": gap,
        "condition_a_attack_before_fim_ready":
            "YES" if attack_a_before_ready else "NO",
        "condition_a_alert":
            "YES" if alert_a else "NO",
        "condition_a_alert_delay_seconds":
            delay_a,
        "condition_b_alert":
            "YES" if alert_b else "NO",
        "condition_b_alert_delay_seconds":
            delay_b,
        "result":
            "VALID"
            if (
                attack_a_before_ready
                and alert_b is not None
            )
            else "REVIEW",
    }

    save_row(row)

    print("\n=== REPETITION RESULT ===")

    for key, value in row.items():
        print(f"{key}={value}")

    return row


for repetition in (2, 3):
    result = run_pair(repetition)

    if result.get("result") != "VALID":
        print(
            f"\n[STOP] Repetition {repetition} "
            "was not valid."
        )
        print(
            "Do not count it. Send the output "
            "before trying again."
        )
        break

print("\n=== CONTROL SCRIPT FINISHED ===")
print(f"CSV: {RESULT_FILE}")
