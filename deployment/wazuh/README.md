# Wazuh SIEM Deployment Guide

This directory contains configuration templates and deployment documentation for the **Wazuh Security Information and Event Management (SIEM)** stack in the homelab.

---

## Architecture Overview

Wazuh is an open-source security monitoring solution providing log management, file integrity monitoring (FIM), endpoint detection and response (EDR), and active response capabilities.

The deployment consists of three core components:
1. **Wazuh Manager**: Analyzes data received from agents, triggers alerts based on rules, and correlates security events.
2. **Wazuh Indexer**: A high-performance search and analytics engine based on OpenSearch, responsible for indexing alerts.
3. **Wazuh Dashboard**: A web-based user interface for alert visualization, threat hunting, and compliance auditing.
4. **Wazuh Agent**: Lightweight daemon installed on endpoints (e.g., Fedora Linux) to gather security logs, audit events, and file integrity data.

---

## Deployment Status

- [x] Reference Docker Compose configuration authored (`docker-compose.yml`).
- [x] Custom local detection rules template created (`config/local_rules.xml`).
- [ ] **TODO**: Provision dedicated container resources (Minimum requirement: 6 GB RAM, 2 vCPUs) for Wazuh Indexer initialization.
- [ ] **TODO**: Enroll the Fedora Linux endpoint agent using TLS authentication.

---

## Sizing and System Requirements

| Component | Minimum RAM | Recommended RAM | Disk Space |
|-----------|-------------|-----------------|------------|
| Wazuh Manager | 2 GB | 4 GB | 20 GB SSD |
| Wazuh Indexer | 4 GB | 8 GB | 50 GB SSD |
| Wazuh Dashboard | 1 GB | 2 GB | 10 GB SSD |
| Wazuh Agent | 50 MB | 100 MB | 500 MB |

> [!WARNING]
> Wazuh Indexer requires `vm.max_map_count` to be set to at least `262144` on the Linux host. Check with `sysctl vm.max_map_count` and set via `sudo sysctl -w vm.max_map_count=262144`.

---

## Deployment Steps

### Step 1: Initialize Custom Configuration Files
The `config/` directory mounts custom rules directly into the manager container.
```bash
# Verify local rules template is present
ls -l deployment/wazuh/config/local_rules.xml
```

### Step 2: Launch Wazuh Single-Node Stack
When system hardware permits, start the Wazuh service profile via Docker Compose:
```bash
docker compose --profile wazuh up -d
```

### Step 3: Accessing the Dashboard
- **URL**: `https://127.0.0.1:443`
- **Default Username**: `admin`
- **Default Password**: Defined in `.env` (`INDEXER_PASSWORD`)

### Step 4: Agent Enrollment Command Template
On the Fedora endpoint, enroll the agent with the manager:
```bash
# For RPM-based distributions (Fedora / RHEL):
sudo WAZUH_MANAGER='172.20.0.10' WAZUH_AGENT_GROUP='default' \
  dnf install -y https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm

# Start and enable the agent service:
sudo systemctl daemon-reload
sudo systemctl enable wazuh-agent
sudo systemctl start wazuh-agent
```

---

## Configuration Files

- `config/local_rules.xml`: Custom rule overrides and lab-specific detection logic.
- `config/ossec.conf`: Base manager configuration defining syscheck scan frequencies and syslog listeners.
