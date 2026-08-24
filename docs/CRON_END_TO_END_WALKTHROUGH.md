# Worked example: malicious cron compromise to accepted recovery

This worked example connects the attack injector, Wazuh alert, Python controller, evidence gate, Terraform replacement, post-recovery checks, monitoring readiness and recorded CSV result for one representative scenario.

The cron scenario injects malicious runtime state at:

- cron definition: `/etc/cron.d/realtime_evil_persistence`
- payload log: `/tmp/realtime-cron.log`

The relevant implementation is spread across the files linked below; this page presents the complete sequence in one place.

## 1. Inject the controlled compromise

[`controller/attack_cron_persistence.py`](../controller/attack_cron_persistence.py) creates the cron definition only after checking that stale attack artefacts are absent. The injected schedule is:

```text
* * * * * root /bin/sh -c 'echo "CRON_PERSISTENCE_ACTIVE $(date --iso-8601=seconds)" >> /tmp/realtime-cron.log'
```

The attack script then waits for the payload marker to appear in `/tmp/realtime-cron.log`. This establishes that the cron mechanism is not merely configured but has executed.

## 2. Wazuh records the filesystem change

The target VM is monitored by a Wazuh agent. Creation or modification of `/etc/cron.d/realtime_evil_persistence` produces a syscheck/File Integrity Monitoring alert on the separate Wazuh Manager.

The recovery controller does **not** simply act on any Wazuh event. [`controller/wazuh_alert_check.py`](../controller/wazuh_alert_check.py) parses candidate JSON alerts and selects an alert only when the following properties match the cron scenario:

```python
if (
    alert_id
    and agent_name == TARGET_AGENT_NAME
    and path == ATTACK_PATH
    and event in {"added", "modified"}
    and "syscheck" in groups
):
    matching_alerts.append(alert)
```

This is an important implementation detail: the selection logic is based on the target agent, exact path, event type and Wazuh syscheck group. The controller does not depend on one hard-coded FIM rule number for this selection step.

The latest matching alert is rejected if it has already been processed. Otherwise its alert ID is saved as the selected alert for this recovery execution.

## 3. Confirm that the compromise is still active

An alert alone is historical evidence that an event occurred. Before destructive recovery, the same alert-check module asks the target whether the malicious cron file still exists:

```python
if target_persistence_exists():
    print("[CONFIRMED] Persistence is still present on target VM.")
    return True
```

If the Wazuh alert exists but the malicious cron state is no longer present, the controller stops without replacing the VM. This is the active-compromise gate.

## 4. Capture the mandatory pre-replacement evidence

[`controller/capture_cron_evidence.py`](../controller/capture_cron_evidence.py) captures six required evidence positions before the VM is stopped:

1. target identity;
2. malicious cron-file contents;
3. cron-file metadata;
4. payload-execution evidence;
5. cron service status;
6. matching Wazuh syscheck/FIM alert.

The script reports `evidence_items_required`, `evidence_items_captured` and `evidence_completeness_percentage`. If any mandatory item is absent, the orchestrator records `FAILED_EVIDENCE_CAPTURE` and does not continue to destructive recovery.

This gate is a protocol-compliance safeguard. It is not presented as a complete forensic acquisition.

## 5. Stop the compromised target

[`controller/orchestrator_cron_recovery.py`](../controller/orchestrator_cron_recovery.py) invokes `controller.quarantine_target` after the evidence gate succeeds.

In thesis terminology this is best described as **stop-based containment**: the compromised VM is stopped before replacement. It is not a claim of live network isolation or a production quarantine capability.

## 6. Remove the stale Wazuh agent identity

Before the replacement VM enrols, the controller invokes [`controller/remove_stale_wazuh_agent.py`](../controller/remove_stale_wazuh_agent.py).

“Stale Wazuh agent cleanup” means removal of the old target VM's Wazuh agent registration so that the replacement instance can establish a clean monitoring identity. Failure at this stage stops the workflow rather than allowing a replacement to be accepted with ambiguous monitoring state.

## 7. Recreate the target through Infrastructure as Code

The orchestrator invokes the replacement module (`controller.recover_replace`), which uses the trusted Terraform configuration under [`Terraform/`](../Terraform/). Terraform requests replacement of the target VM through the Google Cloud control plane.

This stage recreates the infrastructure baseline, but **Terraform success is not the final recovery criterion**. The replacement must still pass security validation and monitoring-readiness checks.

## 8. Check for cron-specific residual indicators

[`controller/validate_cron_recovery.py`](../controller/validate_cron_recovery.py) checks two scenario-specific indicators on the replacement VM:

```text
CRON_ABSENT
PAYLOAD_LOG_ABSENT
```

The controller records two validation indicators for the cron scenario. Both must pass, producing `residual_compromise_count = 0/2`, before the workflow proceeds to monitoring acceptance.

## 9. Demonstrate that monitoring is ready

The same validation module does not treat `wazuh-agent` service state alone as sufficient. It waits until all three conditions hold:

1. the Wazuh agent service is active locally;
2. the Wazuh Manager reports the replacement agent as active;
3. the replacement VM's Wazuh log reports `Real-time file integrity monitoring started.`

Only after those conditions are met does the controller record `fim_realtime_ready = PASS` and `monitoring_restored = PASS`.

The separate A/B readiness control under [`results/controls/fim_readiness_cron_ab_final.csv`](../results/controls/fim_readiness_cron_ab_final.csv) was used to test why service-active and FIM-ready should not be treated as equivalent.

## 10. Record the final outcome

The orchestrator writes one structured CSV row containing detection/confirmation, evidence, containment, stale-agent cleanup, replacement, validation, monitoring and total timing fields, along with evidence and validation counts and the final result.

The five cron rows used in the primary 25-run dataset are identified by [`results/formal_run_manifest.csv`](../results/formal_run_manifest.csv), while the consolidated observations are in [`results/included_main_results.csv`](../results/included_main_results.csv).

A cron run reaches `PASS` only after this complete acceptance path succeeds:

```text
Wazuh alert
   ↓
matching alert selected
   ↓
active cron compromise confirmed
   ↓
6/6 evidence positions captured
   ↓
stop-based containment
   ↓
stale Wazuh identity removed
   ↓
Terraform replacement
   ↓
2/2 cron residual checks pass
   ↓
Wazuh agent + manager + FIM readiness confirmed
   ↓
PASS
```

## Why this example matters

The worked example illustrates the project's main evaluation boundary: **rebuilding the VM is an intermediate recovery milestone, not the point at which recovery is accepted**. The controller accepts recovery only after the injected compromise has been confirmed before destruction, the required evidence checklist has been satisfied, scenario-specific indicators are absent on the replacement and monitoring is demonstrably ready again.
