import csv
import statistics
from pathlib import Path


INPUT = Path("results/included_main_results.csv")

OVERALL_OUTPUT = Path(
    "results/analysis/stage_timing_overall.csv"
)

SCENARIO_OUTPUT = Path(
    "results/analysis/stage_timing_by_scenario.csv"
)

CONTRIBUTION_OUTPUT = Path(
    "results/analysis/stage_contribution_by_scenario.csv"
)


# --------------------------------------------------
# Stage columns
#
# Monitoring restoration is nested inside validation,
# so it is analysed separately and NOT double-counted
# in stage-contribution totals.
# --------------------------------------------------

STAGES = {
    "Detection and active confirmation":
        "detection_check_duration_seconds",

    "Evidence capture":
        "evidence_capture_duration_seconds",

    "Quarantine":
        "quarantine_duration_seconds",

    "Stale Wazuh agent cleanup":
        "stale_agent_cleanup_duration_seconds",

    "IaC replacement":
        "replacement_duration_seconds",

    "Post-recovery validation":
        "validation_duration_seconds",
}

MONITORING_COLUMN = (
    "monitoring_restoration_duration_seconds"
)

TOTAL_COLUMN = "total_duration_seconds"


def to_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def stats(values):
    values = [
        value
        for value in values
        if value is not None
    ]

    if not values:
        return {
            "n": 0,
            "mean": None,
            "median": None,
            "minimum": None,
            "maximum": None,
            "sd": None,
        }

    return {
        "n": len(values),
        "mean": round(statistics.mean(values), 2),
        "median": round(statistics.median(values), 2),
        "minimum": round(min(values), 2),
        "maximum": round(max(values), 2),
        "sd": (
            round(statistics.stdev(values), 2)
            if len(values) > 1
            else 0.0
        ),
    }


with INPUT.open(
    newline="",
    encoding="utf-8-sig",
) as f:
    rows = list(csv.DictReader(f))


print("=== DATASET ===")
print("Rows:", len(rows))

if not rows:
    raise SystemExit("[FAIL] Main dataset is empty.")


columns = set(rows[0].keys())

print("\n=== AVAILABLE TIMING COLUMNS ===")

for column in sorted(columns):
    if "duration" in column.lower():
        print(column)


# --------------------------------------------------
# Resolve validation name if repo uses alternate name
# --------------------------------------------------

validation_candidates = [
    "validation_duration_seconds",
    "post_recovery_validation_duration_seconds",
]

for candidate in validation_candidates:
    if candidate in columns:
        STAGES["Post-recovery validation"] = candidate
        break


required = (
    list(STAGES.values())
    + [TOTAL_COLUMN]
)

missing = [
    column
    for column in required
    if column not in columns
]

if missing:
    print("\n[FAIL] Missing expected columns:")

    for column in missing:
        print(" -", column)

    raise SystemExit(1)


# --------------------------------------------------
# Overall stage statistics
# --------------------------------------------------

overall_rows = []

for stage_name, column in STAGES.items():
    values = [
        to_float(row.get(column))
        for row in rows
    ]

    result = stats(values)

    overall_rows.append({
        "stage": stage_name,
        "column": column,
        **result,
    })


if MONITORING_COLUMN in columns:
    values = [
        to_float(row.get(MONITORING_COLUMN))
        for row in rows
    ]

    result = stats(values)

    overall_rows.append({
        "stage":
            "Monitoring restoration "
            "(nested inside validation)",
        "column": MONITORING_COLUMN,
        **result,
    })


total_result = stats([
    to_float(row.get(TOTAL_COLUMN))
    for row in rows
])

overall_rows.append({
    "stage": "Total workflow",
    "column": TOTAL_COLUMN,
    **total_result,
})


OVERALL_OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True,
)

with OVERALL_OUTPUT.open(
    "w",
    newline="",
    encoding="utf-8",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "stage",
            "column",
            "n",
            "mean",
            "median",
            "minimum",
            "maximum",
            "sd",
        ],
    )

    writer.writeheader()
    writer.writerows(overall_rows)


# --------------------------------------------------
# Per-scenario stage statistics
# --------------------------------------------------

scenarios = sorted(
    set(row["scenario"] for row in rows)
)

scenario_rows = []

for scenario in scenarios:
    scenario_data = [
        row
        for row in rows
        if row["scenario"] == scenario
    ]

    for stage_name, column in STAGES.items():
        result = stats([
            to_float(row.get(column))
            for row in scenario_data
        ])

        scenario_rows.append({
            "scenario": scenario,
            "stage": stage_name,
            **result,
        })

    if MONITORING_COLUMN in columns:
        result = stats([
            to_float(
                row.get(MONITORING_COLUMN)
            )
            for row in scenario_data
        ])

        scenario_rows.append({
            "scenario": scenario,
            "stage":
                "Monitoring restoration "
                "(nested inside validation)",
            **result,
        })

    result = stats([
        to_float(row.get(TOTAL_COLUMN))
        for row in scenario_data
    ])

    scenario_rows.append({
        "scenario": scenario,
        "stage": "Total workflow",
        **result,
    })


with SCENARIO_OUTPUT.open(
    "w",
    newline="",
    encoding="utf-8",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "scenario",
            "stage",
            "n",
            "mean",
            "median",
            "minimum",
            "maximum",
            "sd",
        ],
    )

    writer.writeheader()
    writer.writerows(scenario_rows)


# --------------------------------------------------
# Stage contribution to total workflow
#
# Monitoring restoration is intentionally excluded
# because it is contained within validation.
# --------------------------------------------------

contribution_rows = []

for scenario in scenarios:
    scenario_data = [
        row
        for row in rows
        if row["scenario"] == scenario
    ]

    total_values = [
        to_float(row.get(TOTAL_COLUMN))
        for row in scenario_data
    ]

    total_mean = statistics.mean(
        value
        for value in total_values
        if value is not None
    )

    for stage_name, column in STAGES.items():
        values = [
            to_float(row.get(column))
            for row in scenario_data
        ]

        valid = [
            value
            for value in values
            if value is not None
        ]

        mean_value = statistics.mean(valid)

        percentage = (
            mean_value / total_mean * 100
        )

        contribution_rows.append({
            "scenario": scenario,
            "stage": stage_name,
            "mean_stage_seconds":
                round(mean_value, 2),
            "mean_total_seconds":
                round(total_mean, 2),
            "percentage_of_total":
                round(percentage, 2),
        })


with CONTRIBUTION_OUTPUT.open(
    "w",
    newline="",
    encoding="utf-8",
) as f:
    writer = csv.DictWriter(
        f,
        fieldnames=[
            "scenario",
            "stage",
            "mean_stage_seconds",
            "mean_total_seconds",
            "percentage_of_total",
        ],
    )

    writer.writeheader()
    writer.writerows(contribution_rows)


# --------------------------------------------------
# Console summary
# --------------------------------------------------

print("\n=== OVERALL STAGE TIMINGS ===")

for row in overall_rows:
    print(
        f"{row['stage']} | "
        f"n={row['n']} | "
        f"mean={row['mean']}s | "
        f"median={row['median']}s | "
        f"sd={row['sd']}s"
    )


print("\n=== LARGEST MEAN STAGE PER SCENARIO ===")

for scenario in scenarios:
    candidates = [
        row
        for row in contribution_rows
        if row["scenario"] == scenario
    ]

    largest = max(
        candidates,
        key=lambda row:
            row["mean_stage_seconds"],
    )

    print(
        f"{scenario} | "
        f"{largest['stage']} | "
        f"{largest['mean_stage_seconds']}s | "
        f"{largest['percentage_of_total']}%"
    )


print("\n=== MONITORING RESTORATION ===")

if MONITORING_COLUMN in columns:
    for scenario in scenarios:
        scenario_data = [
            row
            for row in rows
            if row["scenario"] == scenario
        ]

        result = stats([
            to_float(
                row.get(MONITORING_COLUMN)
            )
            for row in scenario_data
        ])

        print(
            f"{scenario} | "
            f"mean={result['mean']}s | "
            f"median={result['median']}s | "
            f"sd={result['sd']}s"
        )

else:
    print(
        "Monitoring restoration column "
        "not present in dataset."
    )


print("\n[OK] Created:")
print(OVERALL_OUTPUT)
print(SCENARIO_OUTPUT)
print(CONTRIBUTION_OUTPUT)
