# Evidence and validation traceability

This note maps the headline thesis counts to the exact controller checks and result fields that produced them. It is intended to make the reported **185/185 pre-replacement evidence-item instances** and **85/85 post-recovery validation checks** auditable without treating those counts as a claim of complete forensic acquisition.

## What the counts mean

The experiment used five compromise scenarios and five formal repetitions per scenario.

The evidence denominator is the number of required evidence positions defined by the scenario-specific capture scripts:

| Scenario | Required evidence positions per run | Formal repetitions | Required evidence-item instances |
|---|---:|---:|---:|
| Unauthorized SSH public key | 6 | 5 | 30 |
| Unauthorized local user | 8 | 5 | 40 |
| Malicious cron job | 6 | 5 | 30 |
| Malicious systemd service | 10 | 5 | 50 |
| Unexpected TCP listener | 7 | 5 | 35 |
| **Total** | **37** | **25 runs** | **185** |

The validation denominator is the number of predefined post-recovery indicators checked by the scenario-specific validation scripts:

| Scenario | Validation indicators per run | Formal repetitions | Validation checks |
|---|---:|---:|---:|
| Unauthorized SSH public key | 2 | 5 | 10 |
| Unauthorized local user | 3 | 5 | 15 |
| Malicious cron job | 2 | 5 | 10 |
| Malicious systemd service | 6 | 5 | 30 |
| Unexpected TCP listener | 4 | 5 | 20 |
| **Total** | **17** | **25 runs** | **85** |

The authoritative per-run observations are in [`results/included_main_results.csv`](../results/included_main_results.csv). The columns `evidence_items_required`, `evidence_items_captured`, `validation_indicators_total`, `validation_indicators_passed`, `residual_compromise_count`, `fim_realtime_ready`, and `final_result` provide the run-level audit trail.

## Exact evidence positions

### Unauthorized SSH public key — 6 positions

Defined in [`controller/capture_ssh_public_key_evidence.py`](../controller/capture_ssh_public_key_evidence.py):

1. target identity;
2. unauthorized key entry;
3. `authorized_keys` metadata;
4. `authorized_keys` SHA-256 hash;
5. SSH service status;
6. matching Wazuh File Integrity Monitoring alert.

### Unauthorized local user — 8 positions

Defined in [`controller/capture_local_user_evidence.py`](../controller/capture_local_user_evidence.py):

1. target identity;
2. unauthorized user account details;
3. group membership;
4. home-directory metadata;
5. `/etc/passwd` entry;
6. `/etc/shadow` entry;
7. sudo-group entry;
8. matching Wazuh alert.

### Malicious cron job — 6 positions

Defined in [`controller/capture_cron_evidence.py`](../controller/capture_cron_evidence.py):

1. target identity;
2. malicious cron-file contents;
3. cron-file metadata;
4. payload-execution evidence;
5. cron service status;
6. matching Wazuh syscheck/FIM alert.

### Malicious systemd service — 10 positions

Defined in [`controller/capture_systemd_evidence.py`](../controller/capture_systemd_evidence.py):

1. target identity;
2. malicious service file;
3. supporting script file;
4. service enabled state;
5. service active state;
6. enablement symlink;
7. running process;
8. heartbeat artefact;
9. file hashes;
10. matching Wazuh syscheck alert.

### Unexpected TCP listener — 7 positions

Defined in [`controller/capture_listener_evidence.py`](../controller/capture_listener_evidence.py):

1. target identity;
2. listening TCP port 4444;
3. PID file;
4. process command line;
5. process executable;
6. listener log file;
7. matching Wazuh listener alert.

## Exact post-recovery validation indicators

### Unauthorized SSH public key — 2 indicators

Defined in [`controller/validate_ssh_public_key_recovery.py`](../controller/validate_ssh_public_key_recovery.py):

1. injected unauthorized key marker is absent;
2. legitimate `authorized_keys` file remains present.

### Unauthorized local user — 3 indicators

Defined in [`controller/validate_local_user_recovery.py`](../controller/validate_local_user_recovery.py):

1. unauthorized account is absent;
2. unauthorized home directory is absent;
3. unauthorized sudo membership is absent.

### Malicious cron job — 2 indicators

Defined in [`controller/validate_cron_recovery.py`](../controller/validate_cron_recovery.py):

1. malicious cron definition is absent;
2. malicious payload log is absent.

### Malicious systemd service — 6 indicators

Defined in [`controller/validate_systemd_recovery.py`](../controller/validate_systemd_recovery.py):

1. malicious service file is absent;
2. supporting script is absent;
3. service is not enabled;
4. service is not active;
5. malicious process is absent;
6. heartbeat artefact is absent.

### Unexpected TCP listener — 4 indicators

Defined in [`controller/validate_listener_recovery.py`](../controller/validate_listener_recovery.py):

1. port 4444 is no longer listening;
2. injected listener process is absent;
3. PID file is absent;
4. listener log file is absent.

## Monitoring readiness is a separate acceptance condition

The 85 validation checks above concern scenario-specific residual indicators. Recovery acceptance additionally requires monitoring readiness. Across all 25 formal runs, the controller required all of the following before accepting monitoring as restored:

- the Wazuh agent service is active on the replacement VM;
- the Wazuh Manager reports the replacement agent as active;
- the replacement agent records that real-time File Integrity Monitoring has started.

The primary CSV records this through `monitoring_restored` and `fim_realtime_ready`. Therefore **85/85** and **25/25 monitoring-ready** describe different controls and should not be merged into one denominator.

## Interpretation boundary

`185/185` means every required evidence position in the declared experimental checklist was captured for every included formal run. It does **not** mean that 185 unique forensic artefacts were acquired, nor does it demonstrate a complete forensic image, memory acquisition, or legal chain of custody.

Likewise, `0` residual indicators means that none of the **predefined indicators for the injected scenario** remained after replacement. It does not prove the absence of every possible unknown compromise.
