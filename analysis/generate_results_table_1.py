import csv
from pathlib import Path


# --- Input summary produced by the analysis pipeline and thesis table output ---
source = Path("results/results_summary_by_scenario.csv")
output = Path("results/table_1_workflow_performance_summary.csv")

rows = []

# --- Read each scenario summary and rename fields into report-friendly headings ---
with source.open(
    newline="",
    encoding="utf-8-sig",
) as file:
    reader = csv.DictReader(file)

    for row in reader:
        rows.append(
            {
                "Scenario": row["scenario_label"],
                "Dataset classification": row["data_quality"],
                "Successful runs (n)": row["included_runs"],
                "Mean duration (s)": row[
                    "mean_total_duration_seconds"
                ],
                "Median duration (s)": row[
                    "median_total_duration_seconds"
                ],
                "Minimum duration (s)": row[
                    "minimum_total_duration_seconds"
                ],
                "Maximum duration (s)": row[
                    "maximum_total_duration_seconds"
                ],
                "Standard deviation (s)": (
                    row["sample_standard_deviation_seconds"]
                    or "N/A"
                ),
                "Detection": row["detection_status"],
                "Evidence capture": row["evidence_status"],
                "Replacement": row["replacement_status"],
                "Validation": row["validation_status"],
                "Monitoring restoration": row[
                    "monitoring_status"
                ],
                "Zero residual compromise": row[
                    "zero_residual_status"
                ],
            }
        )

# --- Write the compact CSV used to build the workflow-performance table ---
with output.open(
    "w",
    newline="",
    encoding="utf-8",
) as file:
    writer = csv.DictWriter(
        file,
        fieldnames=rows[0].keys(),
    )
    writer.writeheader()
    writer.writerows(rows)

print(f"[OK] Thesis summary table created: {output}")
