import csv
import statistics
from collections import Counter
from pathlib import Path


RESULTS_DIR = Path("results")

MAIN_OUTPUT = RESULTS_DIR / "included_main_results.csv"
SUPPLEMENTARY_OUTPUT = (
    RESULTS_DIR / "included_supplementary_results.csv"
)
EXCLUDED_OUTPUT = RESULTS_DIR / "excluded_development_runs.csv"
SUMMARY_OUTPUT = RESULTS_DIR / "results_summary_by_scenario.csv"
README_OUTPUT = RESULTS_DIR / "results_dataset_readme.txt"


STANDARD_FILES = {
    "cron_recovery_formal_results.csv": {
        "label": "Malicious cron persistence",
        "quality": "FORMAL_REPEATED",
    },
    "local_user_recovery_orchestrator_results.csv": {
        "label": "Unauthorized local user",
        "quality": "FORMAL_REPEATED",
    },
    "systemd_recovery_formal_results.csv": {
        "label": "Malicious systemd persistence",
        "quality": "FORMAL_REPEATED",
    },
    "listener_recovery_formal_results.csv": {
        "label": "Unexpected TCP listener",
        "quality": "FORMAL_REPEATED",
    },
}


SSH_FORMAL_TIMESTAMPS = {
    "2026-07-20T23:16:02",
    "2026-07-20T23:28:31",
    "2026-07-21T00:00:18",
    "2026-07-21T00:28:51",
    "2026-07-21T09:44:05",
}


SUPPLEMENTARY_FORMAL_TIMESTAMPS = {
    "2026-07-26T18:36:06+00:00",
    "2026-07-26T20:18:26+00:00",
}


MASTER_FIELDS = [
    "run_id",
    "category",
    "data_quality",
    "scenario",
    "scenario_label",
    "timestamp_utc",
    "source_file",
    "source_row",
    "wazuh_detection",
    "detection_check_duration_seconds",
    "evidence_capture",
    "evidence_capture_duration_seconds",
    "quarantine",
    "quarantine_duration_seconds",
    "stale_agent_cleanup",
    "stale_agent_cleanup_duration_seconds",
    "credential_rotation",
    "credential_rotation_duration_seconds",
    "replacement_recovery",
    "replacement_duration_seconds",
    "post_recovery_validation",
    "validation_duration_seconds",
    "monitoring_restored",
    "new_key_success",
    "old_key_denied",
    "residual_compromise_count",
    "residual_compromise_score",
    "total_duration_seconds",
    "final_result",
    "inclusion_reason",
]


EXCLUDED_FIELDS = [
    "source_file",
    "source_row",
    "timestamp_utc",
    "scenario",
    "final_result",
    "total_duration_seconds",
    "exclusion_reason",
]


EXTENDED_SSH_FIELDS = [
    "timestamp_utc",
    "scenario",
    "wazuh_detection",
    "detection_check_duration_seconds",
    "evidence_capture",
    "evidence_capture_duration_seconds",
    "quarantine",
    "quarantine_duration_seconds",
    "stale_agent_cleanup",
    "stale_agent_cleanup_duration_seconds",
    "credential_rotation",
    "credential_rotation_duration_seconds",
    "replacement_recovery",
    "replacement_duration_seconds",
    "post_recovery_validation",
    "validation_duration_seconds",
    "monitoring_restored",
    "new_key_success",
    "old_key_denied",
    "residual_compromise_count",
    "residual_compromise_score",
    "total_duration_seconds",
    "final_result",
]


def write_csv(path, fields, rows):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as file:
        writer = csv.DictWriter(
            file,
            fieldnames=fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(rows)


def normalise_standard_row(
    row,
    *,
    category,
    quality,
    label,
    source_file,
    source_row,
    reason,
):
    return {
        "category": category,
        "data_quality": quality,
        "scenario": row.get("scenario", ""),
        "scenario_label": label,
        "timestamp_utc": (
            row.get("timestamp_utc")
            or row.get("timestamp")
            or ""
        ),
        "source_file": source_file,
        "source_row": source_row,
        "wazuh_detection": row.get(
            "wazuh_detection",
            "NOT_RECORDED",
        ),
        "detection_check_duration_seconds": row.get(
            "detection_check_duration_seconds",
            "",
        ),
        "evidence_capture": row.get(
            "evidence_capture",
            "NOT_RECORDED",
        ),
        "evidence_capture_duration_seconds": row.get(
            "evidence_capture_duration_seconds",
            "",
        ),
        "quarantine": row.get(
            "quarantine",
            "NOT_RECORDED",
        ),
        "quarantine_duration_seconds": row.get(
            "quarantine_duration_seconds",
            "",
        ),
        "stale_agent_cleanup": row.get(
            "stale_agent_cleanup",
            "NOT_RECORDED",
        ),
        "stale_agent_cleanup_duration_seconds": row.get(
            "stale_agent_cleanup_duration_seconds",
            "",
        ),
        "credential_rotation": "NOT_APPLICABLE",
        "credential_rotation_duration_seconds": "",
        "replacement_recovery": row.get(
            "replacement_recovery",
            "NOT_RECORDED",
        ),
        "replacement_duration_seconds": row.get(
            "replacement_duration_seconds",
            "",
        ),
        "post_recovery_validation": row.get(
            "post_recovery_validation",
            "NOT_RECORDED",
        ),
        "validation_duration_seconds": row.get(
            "validation_duration_seconds",
            "",
        ),
        "monitoring_restored": row.get(
            "monitoring_restored",
            "NOT_RECORDED",
        ) or "NOT_RECORDED",
        "new_key_success": "NOT_APPLICABLE",
        "old_key_denied": "NOT_APPLICABLE",
        "residual_compromise_count": row.get(
            "residual_compromise_count",
            "NOT_RECORDED",
        ) or "NOT_RECORDED",
        "residual_compromise_score": row.get(
            "residual_compromise_score",
            "",
        ),
        "total_duration_seconds": row.get(
            "total_duration_seconds",
            "",
        ),
        "final_result": row.get(
            "final_result",
            "",
        ),
        "inclusion_reason": reason,
    }


def load_standard_results():
    included = []
    excluded = []

    for filename, metadata in STANDARD_FILES.items():
        path = RESULTS_DIR / filename

        with path.open(
            newline="",
            encoding="utf-8-sig",
        ) as file:
            rows = list(csv.DictReader(file))

        pass_rows = [
            (index, row)
            for index, row in enumerate(rows, start=1)
            if row.get("final_result") == "PASS"
        ]

        for index, row in enumerate(rows, start=1):
            if row.get("final_result") == "PASS":
                reason = (
                    "Successful repeated formal run."
                    if metadata["quality"] == "FORMAL_REPEATED"
                    else (
                        "Successful end-to-end run; included "
                        "as preliminary single-run evidence."
                    )
                )

                included.append(
                    normalise_standard_row(
                        row,
                        category="MAIN",
                        quality=metadata["quality"],
                        label=metadata["label"],
                        source_file=filename,
                        source_row=index,
                        reason=reason,
                    )
                )
            else:
                excluded.append(
                    {
                        "source_file": filename,
                        "source_row": index,
                        "timestamp_utc": row.get(
                            "timestamp_utc",
                            "",
                        ),
                        "scenario": row.get(
                            "scenario",
                            "",
                        ),
                        "final_result": row.get(
                            "final_result",
                            "",
                        ),
                        "total_duration_seconds": row.get(
                            "total_duration_seconds",
                            "",
                        ),
                        "exclusion_reason": (
                            "Development, debugging or failed "
                            "workflow run; not used for recovery-"
                            "time performance statistics."
                        ),
                    }
                )

        if metadata["quality"] == "FORMAL_REPEATED":
            if len(pass_rows) != 5:
                print(
                    f"[WARNING] {filename} contains "
                    f"{len(pass_rows)} PASS rows; expected 5."
                )

    return included, excluded


def load_mixed_ssh_results():
    path = (
        RESULTS_DIR
        / "ssh_key_recovery_orchestrator_results.csv"
    )

    included_main = []
    included_supplementary = []
    excluded = []

    with path.open(
        newline="",
        encoding="utf-8-sig",
    ) as file:
        raw_rows = list(csv.reader(file))

    for source_row, raw in enumerate(
        raw_rows[1:],
        start=1,
    ):
        if len(raw) == 11:
            row = dict(zip(raw_rows[0], raw))
            timestamp = row["timestamp"]

            if (
                timestamp in SSH_FORMAL_TIMESTAMPS
                and row["final_result"] == "PASS"
            ):
                record = normalise_standard_row(
                    row,
                    category="MAIN",
                    quality="FORMAL_REPEATED",
                    label=(
                        "Unauthorized SSH public-key "
                        "persistence"
                    ),
                    source_file=path.name,
                    source_row=source_row,
                    reason=(
                        "Included in the five-run formal "
                        "SSH-key persistence dataset."
                    ),
                )

                record["monitoring_restored"] = (
                    "NOT_RECORDED"
                )
                record[
                    "residual_compromise_count"
                ] = "NOT_RECORDED"

                included_main.append(record)

            else:
                reason = (
                    "Initial successful pilot run."
                    if row["final_result"] == "PASS"
                    else (
                        "Development, failed-trigger or "
                        "failed workflow run."
                    )
                )

                excluded.append(
                    {
                        "source_file": path.name,
                        "source_row": source_row,
                        "timestamp_utc": timestamp,
                        "scenario": row["scenario"],
                        "final_result": row["final_result"],
                        "total_duration_seconds": row[
                            "total_duration_seconds"
                        ],
                        "exclusion_reason": reason,
                    }
                )

        elif len(raw) == 23:
            row = dict(zip(EXTENDED_SSH_FIELDS, raw))
            timestamp = row["timestamp_utc"]

            if (
                timestamp
                in SUPPLEMENTARY_FORMAL_TIMESTAMPS
                and row["final_result"] == "PASS"
            ):
                included_supplementary.append(
                    {
                        "category": "SUPPLEMENTARY",
                        "data_quality": (
                            "SUPPLEMENTARY_REPEATED"
                        ),
                        "scenario": row["scenario"],
                        "scenario_label": (
                            "Stolen trusted SSH private key"
                        ),
                        "timestamp_utc": timestamp,
                        "source_file": path.name,
                        "source_row": source_row,
                        "wazuh_detection": row[
                            "wazuh_detection"
                        ],
                        "detection_check_duration_seconds": row[
                            "detection_check_duration_seconds"
                        ],
                        "evidence_capture": row[
                            "evidence_capture"
                        ],
                        "evidence_capture_duration_seconds": row[
                            "evidence_capture_duration_seconds"
                        ],
                        "quarantine": row["quarantine"],
                        "quarantine_duration_seconds": row[
                            "quarantine_duration_seconds"
                        ],
                        "stale_agent_cleanup": row[
                            "stale_agent_cleanup"
                        ],
                        "stale_agent_cleanup_duration_seconds": row[
                            "stale_agent_cleanup_duration_seconds"
                        ],
                        "credential_rotation": row[
                            "credential_rotation"
                        ],
                        "credential_rotation_duration_seconds": row[
                            "credential_rotation_duration_seconds"
                        ],
                        "replacement_recovery": row[
                            "replacement_recovery"
                        ],
                        "replacement_duration_seconds": row[
                            "replacement_duration_seconds"
                        ],
                        "post_recovery_validation": row[
                            "post_recovery_validation"
                        ],
                        "validation_duration_seconds": row[
                            "validation_duration_seconds"
                        ],
                        "monitoring_restored": row[
                            "monitoring_restored"
                        ],
                        "new_key_success": row[
                            "new_key_success"
                        ],
                        "old_key_denied": row[
                            "old_key_denied"
                        ],
                        "residual_compromise_count": row[
                            "residual_compromise_count"
                        ],
                        "residual_compromise_score": row[
                            "residual_compromise_score"
                        ],
                        "total_duration_seconds": row[
                            "total_duration_seconds"
                        ],
                        "final_result": row["final_result"],
                        "inclusion_reason": (
                            "Clean supplementary credential-"
                            "compromise recovery run."
                        ),
                    }
                )
            else:
                excluded.append(
                    {
                        "source_file": path.name,
                        "source_row": source_row,
                        "timestamp_utc": timestamp,
                        "scenario": row["scenario"],
                        "final_result": row["final_result"],
                        "total_duration_seconds": row[
                            "total_duration_seconds"
                        ],
                        "exclusion_reason": (
                            "Development, failed-trigger, "
                            "credential-rotation failure or "
                            "failed replacement run."
                        ),
                    }
                )
        else:
            raise ValueError(
                f"Unexpected column count {len(raw)} "
                f"at source row {source_row}."
            )

    if len(included_main) != 5:
        raise ValueError(
            "Expected five formal SSH-key persistence runs, "
            f"found {len(included_main)}."
        )

    if len(included_supplementary) != 2:
        raise ValueError(
            "Expected two supplementary stolen-key runs, "
            f"found {len(included_supplementary)}."
        )

    return (
        included_main,
        included_supplementary,
        excluded,
    )


def assign_run_ids(rows):
    counters = Counter()

    for row in rows:
        counters[row["scenario"]] += 1
        row["run_id"] = (
            f"{row['scenario']}_"
            f"{counters[row['scenario']]:02d}"
        )


def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def status_summary(values):
    cleaned = [
        value
        for value in values
        if value not in {
            "",
            "NOT_RECORDED",
            "NOT_APPLICABLE",
        }
    ]

    if not cleaned:
        return "NOT_RECORDED"

    return (
        "PASS"
        if all(value == "PASS" for value in cleaned)
        else "MIXED_OR_FAIL"
    )


def zero_residual_summary(rows):
    scores = [
        safe_float(
            row.get("residual_compromise_score")
        )
        for row in rows
    ]

    scores = [
        value
        for value in scores
        if value is not None
    ]

    if not scores:
        return "NOT_RECORDED"

    return (
        "PASS"
        if all(value == 0 for value in scores)
        else "FAIL"
    )


def build_summary(rows):
    groups = {}

    for row in rows:
        groups.setdefault(
            (
                row["category"],
                row["data_quality"],
                row["scenario"],
                row["scenario_label"],
            ),
            [],
        ).append(row)

    summary_rows = []

    for (
        category,
        quality,
        scenario,
        label,
    ), group_rows in groups.items():
        durations = [
            safe_float(
                row["total_duration_seconds"]
            )
            for row in group_rows
        ]

        durations = [
            value
            for value in durations
            if value is not None
        ]

        stdev = (
            statistics.stdev(durations)
            if len(durations) >= 2
            else ""
        )

        summary_rows.append(
            {
                "category": category,
                "data_quality": quality,
                "scenario": scenario,
                "scenario_label": label,
                "included_runs": len(group_rows),
                "mean_total_duration_seconds": round(
                    statistics.mean(durations),
                    2,
                ),
                "median_total_duration_seconds": round(
                    statistics.median(durations),
                    2,
                ),
                "minimum_total_duration_seconds": round(
                    min(durations),
                    2,
                ),
                "maximum_total_duration_seconds": round(
                    max(durations),
                    2,
                ),
                "sample_standard_deviation_seconds": (
                    round(stdev, 2)
                    if stdev != ""
                    else ""
                ),
                "detection_status": status_summary(
                    [
                        row["wazuh_detection"]
                        for row in group_rows
                    ]
                ),
                "evidence_status": status_summary(
                    [
                        row["evidence_capture"]
                        for row in group_rows
                    ]
                ),
                "replacement_status": status_summary(
                    [
                        row["replacement_recovery"]
                        for row in group_rows
                    ]
                ),
                "validation_status": status_summary(
                    [
                        row[
                            "post_recovery_validation"
                        ]
                        for row in group_rows
                    ]
                ),
                "monitoring_status": status_summary(
                    [
                        row["monitoring_restored"]
                        for row in group_rows
                    ]
                ),
                "zero_residual_status": (
                    zero_residual_summary(group_rows)
                ),
            }
        )

    return sorted(
        summary_rows,
        key=lambda row: (
            row["category"],
            row["scenario_label"],
        ),
    )


def main():
    main_rows, excluded_rows = (
        load_standard_results()
    )

    (
        ssh_main,
        supplementary_rows,
        ssh_excluded,
    ) = load_mixed_ssh_results()

    main_rows.extend(ssh_main)
    excluded_rows.extend(ssh_excluded)

    main_rows.sort(
        key=lambda row: row["timestamp_utc"]
    )
    supplementary_rows.sort(
        key=lambda row: row["timestamp_utc"]
    )
    excluded_rows.sort(
        key=lambda row: row["timestamp_utc"]
    )

    assign_run_ids(main_rows)
    assign_run_ids(supplementary_rows)

    write_csv(
        MAIN_OUTPUT,
        MASTER_FIELDS,
        main_rows,
    )

    write_csv(
        SUPPLEMENTARY_OUTPUT,
        MASTER_FIELDS,
        supplementary_rows,
    )

    write_csv(
        EXCLUDED_OUTPUT,
        EXCLUDED_FIELDS,
        excluded_rows,
    )

    summary_rows = build_summary(
        main_rows + supplementary_rows
    )

    summary_fields = [
        "category",
        "data_quality",
        "scenario",
        "scenario_label",
        "included_runs",
        "mean_total_duration_seconds",
        "median_total_duration_seconds",
        "minimum_total_duration_seconds",
        "maximum_total_duration_seconds",
        "sample_standard_deviation_seconds",
        "detection_status",
        "evidence_status",
        "replacement_status",
        "validation_status",
        "monitoring_status",
        "zero_residual_status",
    ]

    write_csv(
        SUMMARY_OUTPUT,
        summary_fields,
        summary_rows,
    )

    readme = """RESULTS DATASET CLASSIFICATION

The original CSV files were preserved unchanged.

Included main dataset:
- Five unauthorized SSH public-key persistence runs.
- Five unauthorized local-user persistence runs.
- Five malicious cron persistence runs.
- Five malicious systemd persistence runs.
- Five unexpected TCP-listener runs.

Included supplementary dataset:
- Two stolen trusted SSH private-key recovery runs.

Exclusions:
- Failed detection/trigger attempts.
- Evidence-capture implementation failures.
- Stale-agent cleanup failures.
- Infrastructure or Terraform replacement failures.
- Validator false positives and target-check implementation failures.
- The first successful SSH-key persistence run, classified as a pilot before
  the five-run formal series.

All five primary persistence scenarios contain five included formal runs.

The stolen-private-key experiment is supplementary because it evaluates
credential compromise and rotation in addition to host replacement.
"""

    README_OUTPUT.write_text(
        readme,
        encoding="utf-8",
    )

    print("[OK] Results datasets created.")
    print(f"[MAIN INCLUDED RUNS] {len(main_rows)}")
    print(
        "[SUPPLEMENTARY INCLUDED RUNS] "
        f"{len(supplementary_rows)}"
    )
    print(f"[EXCLUDED RUNS] {len(excluded_rows)}")

    print("\n=== SCENARIO SUMMARY ===")

    for row in summary_rows:
        print(
            f"{row['scenario_label']} | "
            f"n={row['included_runs']} | "
            f"mean={row['mean_total_duration_seconds']}s | "
            f"median={row['median_total_duration_seconds']}s | "
            f"min={row['minimum_total_duration_seconds']}s | "
            f"max={row['maximum_total_duration_seconds']}s | "
            f"sd={row['sample_standard_deviation_seconds'] or 'N/A'}"
        )


if __name__ == "__main__":
    main()