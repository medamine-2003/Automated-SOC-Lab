# Automation of Deployment and Detection Engineering in an Open-Source SOC Environment

![Infrastructure](https://img.shields.io/badge/Infrastructure-As--Code-blue)
![SIEM](https://img.shields.io/badge/SIEM-Wazuh-00aae6)
![SOAR](https://img.shields.io/badge/SOAR-Shuffle-orange)
![Automation](https://img.shields.io/badge/Automation-Ansible-black)
![Language](https://img.shields.io/badge/Language-Python-yellow)

## Overview

An automated, cloud-native SOC laboratory that addresses two core problems:

1. **Manual infrastructure deployment** — solved with Infrastructure as Code (IaC) via Ansible.
2. **Alert fatigue from static rules** — solved with a custom **Dual-Architecture Tuning Engine** that dynamically injects suppression rules based on asset context and statistical anomalies.

---

## Architecture

Two VMs deployed on Microsoft Azure (or any cloud provider):

### SOC Host (Ubuntu Server 22.04 LTS)
- **Wazuh** — Manager, Indexer, and Dashboard (Docker)
- **Shuffle SOAR** — Orchestration platform (Docker)
- **Tuning Engine** — Custom Python microservices

### Target Endpoint (Windows Server)
- **Sysmon** — System monitoring via SwiftOnSecurity config
- **Wazuh Agent** — Forwards Event Channel logs to the SIEM

---

## Key Features

### Zero-Touch Deployment
Fully automated provisioning of Docker, Wazuh, Shuffle, and Windows agents via **Ansible**.

### Semi-Autonomous Tuning (Human-in-the-Loop)
A Flask-based Python API integrates with Shuffle SOAR. It:
- Enriches incoming alerts
- Queries a local **Asset Context Database**
- Calculates a **Confidence Score**
- Emails analysts an interactive **"Approve Tuning"** button for review

### Autonomous Volumetric Tuning
A standalone Python script that:
- Queries Wazuh logs for high-volume anomalies (e.g., internal scanners)
- If an authorized subnet breaches a threshold → autonomously injects Level-0 XML suppression rules
- Reloads the SIEM automatically

---

## Repository Structure

```
├── inventory.ini             # Ansible inventory (IPs and connection variables)
├── site.yml                  # Master Ansible playbook
├── roles/
│   ├── docker/               # Installs Docker & Docker Compose
│   ├── wazuh/                # Deploys Wazuh SIEM stack via Docker
│   ├── shuffle/              # Deploys Shuffle SOAR via Docker
│   └── windows_agent/        # Deploys Sysmon & Wazuh Agent via WinRM
├── tuning-engine/
│   ├── engine_api.py         # Flask API for Semi-Autonomous SOAR tuning
│   ├── auto_tuner.py         # Standalone script for Autonomous volumetric tuning
│   └── context_db.json       # Asset inventory and rule metadata database
└── README.md
```

---

## Deployment

### Prerequisites

- An Ansible control node (e.g., Kali Linux or Ubuntu)
- Two cloud VMs (1x Linux, 1x Windows) with the following ports open:
  - `22` (SSH), `5985` (WinRM), `1514`, `9200`, `55000`, `3443`, `8000`
- WinRM enabled on the Windows target

### 1. Clone and Configure

Clone the repository, then edit `inventory.ini` with your cloud IPs and credentials:

```ini
[soc_host]
soc_manager ansible_host=<UBUNTU_PUBLIC_IP> ansible_connection=ssh

[soc_host:vars]
ansible_user=<UBUNTU_USER>
ansible_ssh_pass=<UBUNTU_PASSWORD>
ansible_become_password=<UBUNTU_PASSWORD>
ansible_ssh_common_args='-o StrictHostKeyChecking=no'

[windows_agents]
windows_agent1 ansible_host=<WINDOWS_PUBLIC_IP>

[windows_agents:vars]
ansible_user=<WINDOWS_USER>
ansible_password=<WINDOWS_PASSWORD>
ansible_connection=winrm
ansible_winrm_server_cert_validation=ignore
ansible_winrm_transport=basic
ansible_port=5985
```

### 2. Deploy

```bash
ansible-playbook -i inventory.ini site.yml
```

---

## Attack Simulation & Tuning Demo

### Autonomous Tuning — Volumetric Noise

Run an aggressive WinRM brute-force from an authorized scanner subnet (`<PENTEST_SUBNET>` as defined in `auto_tuner.py`):

```bash
crackmapexec winrm <WINDOWS_PUBLIC_IP> -u Administrator -p /path/to/wordlist.txt
```

Then on the SOC host:

```bash
python3 auto_tuner.py
```

The engine detects the anomaly, injects the XML suppression rule, and restarts the SIEM.

### Semi-Autonomous Tuning — Context-Aware

1. Ensure the Shuffle Webhook is active and linked to `ossec.conf`
2. Trigger a target alert on the Windows endpoint
3. Monitor the Shuffle execution flow
4. Check the analyst email inbox for the tuning recommendation and approval link

---

## ⚠️ Security Disclaimer

This project is an **academic proof-of-concept** for a home/cloud lab environment. It uses:
- Self-signed certificates
- Disabled firewall profiles for testing purposes
- Hardcoded variables

**Do not deploy in production** without proper security hardening, secrets management (e.g., Ansible Vault), and TLS certificate verification.
