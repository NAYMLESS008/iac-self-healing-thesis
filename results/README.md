# Results artefacts

This directory separates **primary formal data**, **controls**, **development history** and **generated analysis outputs**.

## Primary thesis dataset

- `formal_run_manifest.csv` — explicit membership of the 25-run final protocol dataset.
- `included_main_results.csv` — normalized primary dataset used for thesis-facing statistics.
- `results_summary_by_scenario.csv` — descriptive scenario summaries.
- `analysis/` — stage-level descriptive outputs.
- `figures/` — generated thesis-facing figures.

The primary dataset contains five repetitions for each scenario:

1. unauthorised SSH public key;
2. unauthorised local user;
3. malicious cron persistence;
4. malicious systemd persistence;
5. unexpected TCP listener (runtime foothold, not reboot persistence).

## Raw scenario histories

Files named `*_formal_results.csv` preserve recorded scenario execution history. A row's presence in a raw history does **not** by itself make it part of the primary 25-run denominator. Membership is defined only by `formal_run_manifest.csv`.

## Controls

`controls/` contains experiments outside the primary denominator, including the stale-alert decision gate, evidence-failure gate and Wazuh FIM-readiness A/B control.

## Development and supplementary history

`excluded_development_runs.csv`, `archive/`, and `included_supplementary_results.csv` retain engineering history and earlier/supplementary experiments for auditability. They are not mixed into the thesis-facing primary success/timing statistics.

## Dataset fingerprint

`included_main_results.csv`

SHA-256: `a6171d1f1246151a9e235df45019779b4573ba7b8b29374e864323f8adb97de7`
