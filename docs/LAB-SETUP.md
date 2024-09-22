# Homelab Setup & Deployment Guide

This guide provides step-by-step instructions to configure, deploy, and validate the **Cybersecurity Homelab – SOC Monitoring, Threat Detection & Incident Response** environment.

---

## 1. Purpose & Scope

The purpose of this guide is to take a fresh Linux machine (Fedora or RHEL recommended; Debian/Ubuntu fully supported) and systematically stand up:
1. An isolated Docker bridge network for security testing.
2. The vulnerable OWASP Juice Shop web target.
3. The Wazuh SIEM stack (Manager, Indexer, Dashboard).
4. The Suricata Network Intrusion Detection System (NIDS).
5. Endpoint auditing controls (`auditd`) and the Wazuh endpoint agent.
6. Validation checks ensuring all telemetry feeds report to the SIEM.

---

## 2. Prerequisites & Hardware Sizing

### Minimum System Requirements
- **Operating System**: Linux (Fedora 38+, RHEL 9+, Ubuntu 22.04 LTS, or Debian 12)
- **CPU**: 4 cores minimum (8 cores recommended for full ELK/Indexer stack)
- **Memory**: Minimum 8 GB RAM (16 GB recommended)
- **Disk Space**: At least 30 GB free storage (SSD preferred)
- **Permissions**: Sudo / root administrative access on the host

### Required Software Packages
Verify and install required tools using your system package manager:

```bash
# On Fedora / RHEL:
sudo dnf install -y git curl python3 python3-pip jq nmap audit openssh-server

# On Debian / Ubuntu:
sudo apt-get update && sudo apt-get install -y git curl python3 python3-pip jq nmap auditd openssh-server
```

### Container Engine Installation
Ensure Docker Engine and Docker Compose V2 (or Podman with `podman-compose`) are installed and enabled:

```bash
sudo systemctl enable --now docker
# Add your user to the docker group (optional, requires re-login):
sudo usermod -aG docker $USER
```

---

## 3. Host System Kernel Tuning

The Wazuh Indexer (OpenSearch backend) requires higher virtual memory limits than default Linux configurations:

```bash
# Check current max map count
sysctl vm.max_map_count

# Temporarily set to recommended threshold
sudo sysctl -w vm.max_map_count=262144

# Persist setting across reboots:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.d/99-wazuh.conf
sudo sysctl --system
```

---

## 4. Step-by-Step Deployment Workflow

```text
  +------------------+     +------------------+     +------------------+
  | 1. Clone & Env   | --> | 2. Health Check  | --> | 3. Launch Docker |
  +------------------+     +------------------+     +------------------+
                                                             |
                                                             v
  +------------------+     +------------------+     +------------------+
  | 6. Validation    | <-- | 5. Endpoint Audit| <-- | 4. Wazuh Manager |
  +------------------+     +------------------+     +------------------+
```

### Step 1: Repository Clone & Environment Setup
```bash
git clone https://github.com/shivasathvik44/cybersecurity-homelab.git
cd cybersecurity-homelab

# Initialize environment configuration from template
cp .env.example .env
chmod 600 .env
```

### Step 2: Run Pre-Flight Health Check
Execute the health check script to confirm commands, memory, and disk space:
```bash
bash scripts/health_check.sh
```

### Step 3: Launch Isolated Container Workloads
Launch OWASP Juice Shop on the isolated `172.20.0.0/16` network:
```bash
docker compose up -d juice-shop

# Verify running container
docker compose ps juice-shop
```
Test access to Juice Shop on localhost only:
```bash
curl -I http://127.0.0.1:3000
```

### Step 4: Deploy Wazuh SIEM (When System RAM Permits)
```bash
# Launch Wazuh Manager
docker compose --profile wazuh up -d wazuh-manager

# Verify manager port is listening
nc -zv 127.0.0.1 1514
```

### Step 5: Configure Fedora Endpoint Telemetry

#### 5.1 Enable Linux Audit System (`auditd`)
```bash
# Load lab audit rules
sudo cp deployment/endpoint/audit/audit.rules /etc/audit/rules.d/homelab.rules
sudo augenrules --load
sudo systemctl restart auditd

# Verify audit rules are active
sudo auditctl -l
```

#### 5.2 Configure Wazuh Agent on Endpoint
Install and point the Wazuh agent to the manager IP:
```bash
sudo WAZUH_MANAGER="172.20.0.10" dnf install -y https://packages.wazuh.com/4.x/yum/wazuh-agent-4.9.0-1.x86_64.rpm
sudo systemctl enable --now wazuh-agent
```

### Step 6: Validation & Sanity Testing
Run the Python test suite to ensure analysis scripts operate correctly:
```bash
python3 -m unittest discover -s tests -v
```

---

## 5. Troubleshooting Common Setup Issues

| Symptom | Probable Cause | Resolution |
|---|---|---|
| `docker compose` fails with permission denied | Docker socket permissions | Run with `sudo` or add user to `docker` group |
| Wazuh indexer exits with code 137 | Out Of Memory (OOM) | Ensure at least 4 GB free RAM available |
| `augenrules: command not found` | Audit package missing | Run `sudo dnf install audit` |
| `curl: (7) Failed to connect` | Container still booting | Wait 15 seconds; verify with `docker compose logs juice-shop` |

---

## 6. Relevant Cross-Links
- [Architecture Details](ARCHITECTURE.md)
- [Network Topology & IP Plan](NETWORK-TOPOLOGY.md)
- [Detection Rules Specification](DETECTION-RULES.md)
- [Troubleshooting Runbook](TROUBLESHOOTING.md)
