# Reproducibility and artefact identification

This repository contains the implementation and analysis artefacts supporting the MSc thesis **“Evaluating Infrastructure-as-Code-Based Recovery from Runtime Compromise in Stateless Cloud Virtual Machines.”**

## Frozen primary dataset

The authoritative primary dataset is:

`results/included_main_results.csv`

SHA-256:

`a6171d1f1246151a9e235df45019779b4573ba7b8b29374e864323f8adb97de7`

The file contains **25 formal runs**, five for each of five compromise scenarios. The hash identifies the exact CSV used for the thesis-facing primary statistics and figures.

## Selection rule

Primary-run membership is declared in:

`results/formal_run_manifest.csv`

The manifest identifies formal runs by **source file + timestamp + scenario**. `analysis/build_frozen_dataset.py` includes manifest-listed rows regardless of whether the recorded `final_result` is `PASS` or non-PASS. Outcome is therefore not the inclusion criterion.

Rows outside the manifest are retained as development, superseded-protocol, control or outside-series history and are not used in the primary denominator.

## Environment captured for the final experiment

| Component | Recorded configuration |
|---|---|
| Target workload | GCP Compute Engine `e2-micro`, Ubuntu 22.04 LTS, replaceable stateless role |
| Controller host | Windows AMD64, Python 3.12.10 |
| IaC toolchain | Terraform 1.15.5; Google provider constraint `~> 6.0`, resolved to 6.50.0 |
| Administrative path | Google Cloud SDK 573.0.0; IAP-assisted SSH; `europe-west1-b` |
| Monitoring | Wazuh 4.14.5; separate trusted manager VM in the same GCP project; TCP 1514 events / TCP 1515 enrolment |

The evaluated Google Cloud location was **region `europe-west1`, zone `europe-west1-b`**. The checked-in Terraform variable defaults match that evaluated location. A machine-local `terraform.tfvars` may still override those defaults for replication.

## Machine-local prerequisites

Several runtime files are intentionally excluded from version control because they contain machine-specific paths or sensitive material. A fresh clone therefore requires local configuration before the complete recovery workflow can be executed:

- `Terraform/terraform.tfvars` supplies deployment-specific values such as `project_id`, `public_key_path`, `allowed_ssh_cidr`, and `wazuh_manager_ip`;
- SSH private keys and generated replacement keys remain outside the repository;
- `controller/ssh_rotation_state.json` records the local paths of the current/previous trusted SSH keys after credential rotation and is intentionally ignored by Git;
- systemd- and listener-related evidence/validation helpers that use the direct SSH/IAP path expect that local rotation state to exist.

In the evaluated environment, `controller/rotate_compromised_ssh_key.py` created the rotation state as part of the SSH credential-rotation workflow. On another workstation, the local key path/state must be initialised for that machine before executing helpers that depend on it. These exclusions protect credentials and machine-local state; they do not alter the frozen result CSVs or analysis outputs.

## Measurement boundary

`total_duration_seconds` begins when the controller/orchestrator starts and ends when the final outcome is recorded.

It **does not** include:

- attacker dwell time;
- attack-to-Wazuh-alert latency;
- human investigation/authorisation before controller start.

For that reason, `detection_check_duration_seconds` is **controller-side alert retrieval + active-state confirmation**, not Mean Time to Detect (MTTD).

`replacement_duration_seconds` is the **controller-measured IaC replacement stage**, not a pure cloud-provider provisioning timer. The timed replacement module includes Terraform forced replacement and its immediate readiness checks for IAP reachability and local Wazuh-agent service activity before returning control to scenario-specific post-recovery validation.

Monitoring-restoration duration is nested inside post-recovery validation and must not be added to the total a second time.

## Rebuilding the primary outputs

From the repository root:

```bash
python analysis/build_frozen_dataset.py
python analysis/analyze_stage_timings.py
python analysis/generate_results_table_1.py
python analysis/generate_results_figure_1.py
python analysis/generate_stage_timing_figure.py
```

After rebuilding, verify the primary CSV:

### Linux / macOS

```bash
sha256sum results/included_main_results.csv
```

### Windows PowerShell

```powershell
Get-FileHash results/included_main_results.csv -Algorithm SHA256
```

Expected value:

`a6171d1f1246151a9e235df45019779b4573ba7b8b29374e864323f8adb97de7`

## Controls outside the 25-run denominator

The repository also retains targeted controls under `results/controls/`:

- stale-alert decision control;
- mandatory evidence-gate failure control;
- three-pair Wazuh FIM-readiness A/B control.

These controls test decision/readiness boundaries and are intentionally analysed separately from the 25 formal recovery runs.

## Sensitive and machine-local artefacts

The repository intentionally excludes or ignores:

- Terraform state and `.tfvars`;
- SSH private/generated attacker keys;
- `.env` files;
- evidence directories and logs;
- controller runtime alert/rotation state;
- virtual environments and editor/cache files.

Cloud project identifiers, VM names, agent identifiers and public SSH keys may appear in archived implementation output because they were part of the evaluated environment. They are not authentication secrets; private keys and credentials are excluded from the public artefact.

## Interpretation limits

The experiment supports feasibility and repeatable execution under the declared conditions. It does not establish population-level reliability, universal compromise removal, a complete legal chain of custody, live network quarantine, or general performance across other clouds, operating systems, stateful workloads or multi-host incidents.
