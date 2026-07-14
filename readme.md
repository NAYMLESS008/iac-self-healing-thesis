# 🛡️ IaC-Based Replacement Recovery for Compromised Cloud Virtual Machines

![Terraform](https://img.shields.io/badge/Terraform-IaC-623CE4?logo=terraform)
![Python](https://img.shields.io/badge/Python-3.x-3776AB?logo=python)
![Google Cloud](https://img.shields.io/badge/Google%20Cloud-GCP-4285F4?logo=googlecloud)
![Wazuh](https://img.shields.io/badge/Wazuh-4.14-005571)

> MSc Cybersecurity Research Project – Technological University Dublin

## Overview

This project implements an Infrastructure-as-Code (IaC) based replacement recovery workflow for cloud virtual machines that experience runtime persistence attacks.

The workflow uses Terraform to provision and replace cloud infrastructure, Wazuh to detect attacks, and Python controllers to automate evidence collection, recovery and validation.

---

# Research Question

> **How effective is an Infrastructure-as-Code (IaC)-based replacement recovery workflow at restoring a compromised cloud virtual machine following runtime persistence attacks?**

---

# Research Aim

Design, implement and evaluate an IaC-based replacement recovery workflow capable of:

- Detecting runtime persistence attacks
- Preserving forensic evidence
- Automatically rebuilding compromised virtual machines
- Restoring trusted monitoring
- Evaluating recovery using quantitative metrics

---

# Architecture

```text
                 Runtime Persistence Attack
                           │
                           ▼
                   Target Cloud VM
                    (Wazuh Agent)
                           │
                           ▼
                    Wazuh Manager
                           │
                           ▼
              External Python Controller
                           │
          ┌────────────────┴────────────────┐
          │                                 │
          ▼                                 ▼
   Capture Evidence              Terraform Replace VM
          │                                 │
          └────────────────┬────────────────┘
                           ▼
                  New Target VM Created
                           │
                           ▼
           Startup Script installs Wazuh Agent
                           │
                           ▼
               Recovery Validation & Logging
```

---

# Features

- Terraform-based cloud provisioning
- Runtime persistence detection using Wazuh
- Automated Wazuh Agent deployment
- Evidence capture before destructive recovery
- Terraform replacement recovery
- Recovery validation
- Experimental logging

---

# Evaluation Metrics

| Metric | Purpose |
|---------|---------|
| End-to-End Recovery Time | Recovery speed |
| Recovery Effectiveness Rate | Reliability |
| Residual Compromise Score | Remaining persistence |
| Monitoring Restoration Time | Return to monitored state |
| Evidence Completeness Score | Quality of evidence capture |

---

# Project Structure

```text
iac-self-healing-thesis/
├── Terraform/
├── controller/
├── evidence/
├── results/
└── README.md
```

---

# Controllers

## wazuh_alert_check.py
Checks Wazuh alerts before recovery.

## cron_self_heal.py
Prototype in-place recovery controller used during early development.

## recover_replace.py
Performs Terraform replacement recovery.

---

# Current Progress

## Completed

- Terraform deployment
- Separate Wazuh Manager
- Automatic Wazuh Agent installation
- Realtime File Integrity Monitoring
- Cron persistence detection
- Evidence capture
- Automated Terraform replacement
- Recovery validation
- Experiment logging

## In Progress

- Additional persistence attacks
- Quantitative evaluation
- Statistical analysis
- Dissertation writing

---

# Author

**Adith Menon**

MSc Computing (Applied Cyber Security)

Technological University Dublin