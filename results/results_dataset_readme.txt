RESULTS DATASET CLASSIFICATION

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
