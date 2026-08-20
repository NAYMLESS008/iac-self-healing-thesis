RESULTS DATASET CLASSIFICATION

Primary thesis dataset:
- Five unauthorized SSH public-key persistence runs.
- Five unauthorized local-user persistence runs.
- Five malicious cron persistence runs.
- Five malicious systemd persistence runs.
- Five unexpected TCP-listener runs.
- Total primary runs: 25.

All 25 primary runs completed the final defined workflow with PASS.

Historical supplementary data:
- Two stolen trusted SSH private-key recovery runs are preserved in
  included_supplementary_results.csv.
- The stolen-key experiment is outside the final thesis scope and is excluded
  from thesis-facing summaries, tables, figures, and the primary success rate.

Archived outside-protocol data:
- One additional successful cron execution from 2026-08-06 is preserved in
  results/archive but is not part of the predefined five-run cron series.

Excluded development data:
- Development, debugging, failed-trigger, failed-evidence, transport,
  validation, and superseded-protocol attempts are retained separately in
  excluded_development_runs.csv.

Interpretation:
- The primary dataset uses five repetitions for each of the five selected
  persistence scenarios.
- Results are analysed descriptively using success outcomes, evidence
  completeness, residual indicators, monitoring restoration, stage durations,
  total workflow duration, and run-to-run variability.
