"""Rebuild the frozen 25-run thesis dataset from an explicit run manifest.

Primary-run membership is determined only by results/formal_run_manifest.csv.
The final_result field is copied as an observed outcome and is never used as
an inclusion filter.
"""

import csv
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
MANIFEST = RESULTS / "formal_run_manifest.csv"
OUTPUT = RESULTS / "included_main_results.csv"

SCENARIOS = {
    "unauthorized_ssh_public_key": ("ssh_public_key_recovery_formal_results.csv", "Unauthorized SSH public-key persistence"),
    "unauthorized_local_user": ("local_user_recovery_formal_results.csv", "Unauthorized local user"),
    "malicious_cron_persistence": ("cron_recovery_formal_results.csv", "Malicious cron persistence"),
    "malicious_systemd_persistence": ("systemd_recovery_formal_results.csv", "Malicious systemd persistence"),
    "unexpected_listener": ("listener_recovery_formal_results.csv", "Unexpected TCP listener"),
}

FIELDS = [
    "run_id", "category", "data_quality", "scenario", "scenario_label",
    "timestamp_utc", "source_file", "source_row", "wazuh_detection",
    "detection_check_duration_seconds", "evidence_capture",
    "evidence_capture_duration_seconds", "evidence_items_required",
    "evidence_items_captured", "evidence_completeness_percentage",
    "quarantine", "quarantine_duration_seconds", "stale_agent_cleanup",
    "stale_agent_cleanup_duration_seconds", "credential_rotation",
    "credential_rotation_duration_seconds", "replacement_recovery",
    "replacement_duration_seconds", "post_recovery_validation",
    "validation_duration_seconds", "validation_indicators_total",
    "validation_indicators_passed", "validation_success_percentage",
    "monitoring_restored", "fim_realtime_ready",
    "monitoring_restoration_duration_seconds", "new_key_success",
    "old_key_denied", "residual_compromise_count",
    "residual_compromise_score", "total_duration_seconds", "final_result",
    "inclusion_reason",
]


def read_csv(path):
    with path.open(newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def value(row, key, default=""):
    item = row.get(key, default)
    return default if item is None else item


def normalise(row, scenario, label, source_file, source_row, run_id):
    is_ssh = scenario == "unauthorized_ssh_public_key"
    is_cron = scenario == "malicious_cron_persistence"
    return {
        "run_id": run_id,
        "category": "MAIN",
        "data_quality": "FORMAL_REPEATED",
        "scenario": scenario,
        "scenario_label": label,
        "timestamp_utc": value(row, "timestamp_utc") or value(row, "timestamp"),
        "source_file": source_file,
        "source_row": source_row,
        "wazuh_detection": value(row, "wazuh_detection", "NOT_RECORDED"),
        "detection_check_duration_seconds": value(row, "detection_check_duration_seconds"),
        "evidence_capture": value(row, "evidence_capture", "NOT_RECORDED"),
        "evidence_capture_duration_seconds": value(row, "evidence_capture_duration_seconds"),
        "evidence_items_required": value(row, "evidence_items_required", "NOT_RECORDED"),
        "evidence_items_captured": value(row, "evidence_items_captured", "NOT_RECORDED"),
        "evidence_completeness_percentage": value(row, "evidence_completeness_percentage", "NOT_RECORDED"),
        "quarantine": value(row, "quarantine", "NOT_RECORDED"),
        "quarantine_duration_seconds": value(row, "quarantine_duration_seconds"),
        "stale_agent_cleanup": value(row, "stale_agent_cleanup", "NOT_RECORDED"),
        "stale_agent_cleanup_duration_seconds": value(row, "stale_agent_cleanup_duration_seconds"),
        "credential_rotation": value(row, "credential_rotation", "NOT_APPLICABLE") if is_ssh else "NOT_APPLICABLE",
        "credential_rotation_duration_seconds": value(row, "credential_rotation_duration_seconds") if is_ssh else "",
        "replacement_recovery": value(row, "replacement_recovery", "NOT_RECORDED"),
        "replacement_duration_seconds": value(row, "replacement_duration_seconds"),
        "post_recovery_validation": value(row, "post_recovery_validation", "NOT_RECORDED"),
        "validation_duration_seconds": value(row, "validation_duration_seconds"),
        "validation_indicators_total": value(row, "validation_indicators_total", "NOT_RECORDED"),
        "validation_indicators_passed": value(row, "validation_indicators_passed", "NOT_RECORDED"),
        "validation_success_percentage": value(row, "validation_success_percentage", "NOT_RECORDED"),
        "monitoring_restored": value(row, "monitoring_restored", "NOT_RECORDED") or "NOT_RECORDED",
        "fim_realtime_ready": value(row, "fim_realtime_ready", "NOT_RECORDED") or "NOT_RECORDED",
        "monitoring_restoration_duration_seconds": value(row, "monitoring_restoration_duration_seconds"),
        "new_key_success": value(row, "new_key_success", "NOT_APPLICABLE") if is_ssh else "NOT_APPLICABLE",
        "old_key_denied": value(row, "old_key_denied", "NOT_APPLICABLE") if is_ssh else "NOT_APPLICABLE",
        "residual_compromise_count": value(row, "residual_compromise_count", "NOT_RECORDED") or "NOT_RECORDED",
        "residual_compromise_score": value(row, "residual_compromise_score"),
        "total_duration_seconds": value(row, "total_duration_seconds"),
        "final_result": value(row, "final_result"),
        "inclusion_reason": (
            "Final-protocol cron run with full FIM-readiness criterion."
            if is_cron
            else "Successful repeated formal run."
        ),
    }


def main():
    manifest = read_csv(MANIFEST)
    if len(manifest) != 25:
        raise SystemExit(f"Expected 25 manifest rows; found {len(manifest)}")

    counts = Counter(item["scenario"] for item in manifest)
    if set(counts) != set(SCENARIOS) or any(count != 5 for count in counts.values()):
        raise SystemExit(f"Expected five runs for each scenario; found {dict(counts)}")

    sources = {}
    for scenario, (filename, _) in SCENARIOS.items():
        rows = read_csv(RESULTS / filename)
        sources[filename] = {
            (value(row, "timestamp_utc") or value(row, "timestamp")): (index, row)
            for index, row in enumerate(rows, start=1)
        }

    counters = Counter()
    output_rows = []
    for item in manifest:
        scenario = item["scenario"]
        expected_file, label = SCENARIOS[scenario]
        source_file = item["source_file"]
        timestamp = item["timestamp_utc"]
        if source_file != expected_file:
            raise SystemExit(f"Unexpected source file for {scenario}: {source_file}")
        if timestamp not in sources[source_file]:
            raise SystemExit(f"Manifest run not found: {source_file} @ {timestamp}")

        source_row, row = sources[source_file][timestamp]
        if value(row, "scenario") != scenario:
            raise SystemExit(f"Scenario mismatch: {source_file} @ {timestamp}")
        if value(row, "fim_realtime_ready", "NOT_RECORDED") in {"", "NOT_RECORDED"}:
            raise SystemExit(f"Final-protocol run lacks FIM readiness: {source_file} @ {timestamp}")

        counters[scenario] += 1
        run_id = f"{scenario}_{counters[scenario]:02d}"
        output_rows.append(normalise(row, scenario, label, source_file, source_row, run_id))

    with OUTPUT.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"[OK] Wrote {len(output_rows)} frozen formal runs to {OUTPUT}")
    print(f"[OBSERVED OUTCOME] {sum(r['final_result'] == 'PASS' for r in output_rows)}/25 PASS")


if __name__ == "__main__":
    main()
