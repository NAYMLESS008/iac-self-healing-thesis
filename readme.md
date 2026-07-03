# Terraform-Based Self-Healing VM Prototype

## Overview

This MSc cybersecurity thesis prototype explores Infrastructure-as-Code (IaC) self-healing using Terraform and Python.

A Google Cloud Ubuntu VM is provisioned with Terraform. A runtime compromise is simulated by adding an unauthorized SSH key. The system detects the drift, restores the trusted SSH configuration, and verifies that attacker access is removed.

---

## Components

* **Terraform**: VM provisioning
* **baseline.json**: Trusted SSH key baseline
* **monitor.py**: Drift detection
* **repair.py**: Baseline restoration
* **validate.py**: Recovery validation

---

## Project Structure

```text
iac-self-healing-thesis
├── Terraform/
├── controller/
│   ├── baseline.json
│   ├── monitor.py
│   ├── repair.py
│   └── validate.py
├── attacks/
└── readme.md
```

---

## MAPE-K Mapping

| Component | Implementation                         |
| --------- | -------------------------------------- |
| Monitor   | `monitor.py` reads VM SSH keys         |
| Analyze   | Compares keys against `baseline.json`  |
| Plan      | Restore trusted baseline               |
| Execute   | `repair.py` replaces `authorized_keys` |
| Knowledge | `baseline.json`                        |
| Validate  | `validate.py` tests attacker access    |

---

## Deployment

```cmd
cd C:\iac-self-healing-thesis\Terraform
terraform init
terraform apply
```

Terraform creates:

* Ubuntu VM
* SSH firewall rule

SSH access:

```cmd
ssh -i "%USERPROFILE%\.ssh\gcp_thesis_vm" thesisadmin@<VM_EXTERNAL_IP>
```

---

## Baseline Creation

The trusted state is captured from:

```bash
~/.ssh/authorized_keys
```

and stored in:

```text
controller\baseline.json
```

---

## Monitoring

Run:

```cmd
python controller\monitor.py
```

Expected outputs:

```text
[CLEAN] VM SSH keys match the trusted baseline.
```

or

```text
[DRIFT DETECTED] VM SSH keys do not match the baseline.
```

---

## Attack Simulation

Generate attacker key:

```cmd
ssh-keygen -t ed25519 -f attacks\attacker_key -C "simulated-attacker-key"
```

Inject attacker key:

```cmd
type attacks\attacker_key.pub | ssh -i "%USERPROFILE%\.ssh\gcp_thesis_vm" thesisadmin@<VM_EXTERNAL_IP> "cat >> ~/.ssh/authorized_keys"
```

Monitor output:

```text
[DRIFT DETECTED] VM SSH keys do not match the baseline.
```

---

## Repair

Run:

```cmd
python controller\repair.py
```

Expected output:

```text
[REPAIR COMPLETE] authorized_keys has been restored to the trusted baseline.
```

Verify:

```cmd
python controller\monitor.py
```

Output:

```text
[CLEAN] VM SSH keys match the trusted baseline.
```

---

## Validation

Test attacker access:

```cmd
ssh -i attacks\attacker_key -o BatchMode=yes thesisadmin@<VM_EXTERNAL_IP>
```

Expected result:

```text
Permission denied (publickey).
```

Or run:

```cmd
python controller\validate.py
```

Expected output:

```text
[VALIDATION PASSED]
[SECURITY RESTORED]
```

---

## Experiment Flow

```text
Deploy VM
    ↓
Create baseline
    ↓
Monitor (clean)
    ↓
Inject attacker key
    ↓
Monitor (drift detected)
    ↓
Repair
    ↓
Monitor (clean)
    ↓
Validate attacker access denied
```

---

## Limitations

* Only SSH-key persistence is tested
* Attack injection is manual
* Single VM environment
* Repair is in-place rather than full rebuild
* Scripts are manually executed

---

## Future Work

* Automated controller workflow
* Additional persistence checks (cron jobs, users)
* Firewall and configuration drift detection
* Recovery timing measurements
* Comparison with full VM rebuild strategies

---

## Summary

The prototype demonstrates a simple self-healing workflow: provision a VM with Terraform, detect unauthorized SSH-key persistence, restore the trusted baseline, and verify that attacker access is removed.
