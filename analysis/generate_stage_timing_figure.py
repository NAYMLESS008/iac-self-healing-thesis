import csv
from pathlib import Path

import matplotlib.pyplot as plt


INPUT = Path(
    "results/analysis/stage_contribution_by_scenario.csv"
)

OUTPUT = Path(
    "results/figures/figure_2_mean_stage_duration_by_scenario.png"
)


SCENARIO_ORDER = [
    "malicious_cron_persistence",
    "malicious_systemd_persistence",
    "unauthorized_ssh_public_key",
    "unauthorized_local_user",
    "unexpected_listener",
]

SCENARIO_LABELS = {
    "malicious_cron_persistence":
        "Cron",
    "malicious_systemd_persistence":
        "Systemd",
    "unauthorized_ssh_public_key":
        "SSH public key",
    "unauthorized_local_user":
        "Local user",
    "unexpected_listener":
        "TCP listener",
}


STAGE_ORDER = [
    "Detection and active confirmation",
    "Evidence capture",
    "Quarantine",
    "Stale Wazuh agent cleanup",
    "IaC replacement",
    "Post-recovery validation",
]


STAGE_LABELS = {
    "Detection and active confirmation":
        "Detection + confirmation",
    "Evidence capture":
        "Evidence capture",
    "Quarantine":
        "Quarantine",
    "Stale Wazuh agent cleanup":
        "Wazuh agent cleanup",
    "IaC replacement":
        "IaC replacement",
    "Post-recovery validation":
        "Post-recovery validation",
}


with INPUT.open(
    newline="",
    encoding="utf-8-sig",
) as f:
    rows = list(csv.DictReader(f))


data = {
    scenario: {
        stage: 0.0
        for stage in STAGE_ORDER
    }
    for scenario in SCENARIO_ORDER
}


for row in rows:
    scenario = row["scenario"]
    stage = row["stage"]

    if (
        scenario in data
        and stage in STAGE_ORDER
    ):
        data[scenario][stage] = float(
            row["mean_stage_seconds"]
        )


labels = [
    SCENARIO_LABELS[scenario]
    for scenario in SCENARIO_ORDER
]

bottom = [0.0] * len(SCENARIO_ORDER)


plt.figure(figsize=(11, 7))


for stage in STAGE_ORDER:

    values = [
        data[scenario][stage]
        for scenario in SCENARIO_ORDER
    ]

    plt.bar(
        labels,
        values,
        bottom=bottom,
        label=STAGE_LABELS[stage],
    )

    bottom = [
        current + value
        for current, value
        in zip(bottom, values)
    ]


plt.ylabel("Mean duration (seconds)")

plt.xlabel("Persistence scenario")

plt.title(
    "Mean Workflow Stage Duration by Persistence Scenario"
)

plt.legend(
    title="Workflow stage",
    loc="upper left",
)

plt.grid(
    axis="y",
    alpha=0.25,
)

plt.tight_layout()


OUTPUT.parent.mkdir(
    parents=True,
    exist_ok=True,
)

plt.savefig(
    OUTPUT,
    dpi=300,
    bbox_inches="tight",
)

plt.close()


print("[OK] Figure created:")
print(OUTPUT)

print("\n=== VALUES USED ===")

for scenario in SCENARIO_ORDER:
    print(
        f"\n{SCENARIO_LABELS[scenario]}"
    )

    total = 0.0

    for stage in STAGE_ORDER:
        value = data[scenario][stage]
        total += value

        print(
            f"  {STAGE_LABELS[stage]}: "
            f"{value:.2f}s"
        )

    print(
        f"  Stage sum: {total:.2f}s"
    )
