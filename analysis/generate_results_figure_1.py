import csv
import statistics
from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.lines import Line2D


# --- Dataset and output locations ---
RESULTS_DIR = Path("results")
FIGURES_DIR = RESULTS_DIR / "figures"

MAIN_FILE = RESULTS_DIR / "included_main_results.csv"
SUPPLEMENTARY_FILE = (
    RESULTS_DIR / "included_supplementary_results.csv"
)

OUTPUT_FILE = (
    FIGURES_DIR
    / "figure_1_total_workflow_duration_by_scenario.png"
)

# Fixed display order keeps the figure consistent with the report.
SCENARIO_ORDER = [
    "Unauthorized SSH public-key persistence",
    "Unauthorized local user",
    "Malicious cron persistence",
    "Malicious systemd persistence",
    "Unexpected TCP listener",
    "Stolen trusted SSH private key",
]


# --- Read one CSV into a list of dictionaries ---
def read_rows(path):
    with path.open(
        newline="",
        encoding="utf-8-sig",
    ) as file:
        return list(csv.DictReader(file))


# --- Create small horizontal offsets so repeated run markers do not overlap ---
def create_offsets(count):
    if count == 1:
        return [0.0]

    start = -0.16
    end = 0.16
    step = (end - start) / (count - 1)

    return [
        start + (step * index)
        for index in range(count)
    ]


def main():
    # --- Prepare output directory and load the frozen main dataset ---
    FIGURES_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    rows = read_rows(MAIN_FILE)

    # Group the recorded total workflow durations by scenario label.
    durations_by_scenario = {
        scenario: []
        for scenario in SCENARIO_ORDER
    }

    for row in rows:
        label = row["scenario_label"]

        if label in durations_by_scenario:
            durations_by_scenario[label].append(
                float(row["total_duration_seconds"])
            )

    # --- Draw each included run as a point and the scenario mean as a line ---
    figure, axis = plt.subplots(
        figsize=(12, 7),
    )

    for position, scenario in enumerate(
        SCENARIO_ORDER,
        start=1,
    ):
        durations = durations_by_scenario[scenario]

        if not durations:
            continue

        offsets = create_offsets(len(durations))

        x_values = [
            position + offset
            for offset in offsets
        ]

        axis.scatter(
            x_values,
            durations,
            s=65,
            zorder=3,
        )

        mean_duration = statistics.mean(durations)

        axis.hlines(
            mean_duration,
            position - 0.23,
            position + 0.23,
            linewidth=2.5,
            zorder=2,
        )

        axis.annotate(
            f"Mean: {mean_duration:.2f}s\nn={len(durations)}",
            xy=(position, mean_duration),
            xytext=(0, 12),
            textcoords="offset points",
            ha="center",
            fontsize=9,
        )

    # --- Human-readable axis labels used in the report figure ---
    display_labels = [
        "SSH public-key\npersistence",
        "Unauthorized\nlocal user",
        "Malicious cron\npersistence",
        "Malicious systemd\npersistence",
        "Unexpected TCP\nlistener",
        "Stolen private key\n(supplementary)",
    ]

    axis.set_xticks(
        range(1, len(SCENARIO_ORDER) + 1),
        display_labels,
    )

    axis.set_ylim(bottom=0)

    axis.set_ylabel(
        "Total end-to-end recovery duration (seconds)"
    )

    axis.set_xlabel(
        "Runtime persistence or credential-compromise scenario"
    )

    axis.set_title(
        "Total End-to-End Recovery Duration by Scenario"
    )

    axis.grid(
        axis="y",
        linestyle="--",
        alpha=0.5,
    )

    # Legend explains the point markers versus horizontal mean lines.
    legend_items = [
        Line2D(
            [0],
            [0],
            marker="o",
            linestyle="None",
            label="Individual included run",
        ),
        Line2D(
            [0],
            [0],
            linewidth=2.5,
            label="Scenario mean",
        ),
    ]

    axis.legend(
        handles=legend_items,
        loc="upper right",
    )

    # --- Save a high-resolution PNG for the report ---
    figure.tight_layout()

    figure.savefig(
        OUTPUT_FILE,
        dpi=300,
        bbox_inches="tight",
    )

    plt.close(figure)

    print(f"[OK] Figure created: {OUTPUT_FILE}")


if __name__ == "__main__":
    main()