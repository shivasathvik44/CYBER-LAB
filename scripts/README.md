# Homelab Automation Scripts

This directory houses production-ready, standalone security automation scripts developed for log parsing, file integrity monitoring, and environment health checks.

---

## Script Overview

| Script | Purpose | Language | Requirements |
|--------|---------|----------|--------------|
| `log_analyzer.py` | Detect brute-force attacks, password spraying, and post-failure compromises | Python 3.10+ | Standard Library |
| `integrity_monitor.py` | Create and verify SHA-256 cryptographic baselines (FIM) | Python 3.10+ | Standard Library |
| `health_check.sh` | Validate container runtimes, RAM, disk space, and open ports | Bash | Standard GNU coreutils |
| `run_ssh_demo.sh` | Shortcut wrapper to execute Phase 2 SSH brute-force analysis demonstration | Bash | Bash, Python 3 |
| `run_fim_demo.sh` | Shortcut wrapper to execute Phase 1 File Integrity Monitoring demonstration | Bash | Bash, Python 3 |

---

## 1. Authentication Log Analyzer (`log_analyzer.py`)

### Features
- Analyzes `/var/log/secure` (Fedora/RHEL), `/var/log/auth.log` (Debian/Ubuntu), and sample log streams.
- Identifies and aggregates failed password attempts by source IP address.
- Detects **High-Volume Brute Force** (`SSH_BRUTE_FORCE`) exceeding configurable attempt thresholds.
- Detects **Horizontal Password Spraying** (`PASSWORD_SPRAYING`) across configurable distinct account thresholds.
- Detects **Compromise Warnings** (`SUCCESS_AFTER_FAILURES`): Flags successful logins following repeated failures.
- Tracks targeted usernames and timestamps (first seen / last seen).
- Supports both positional file arguments and `-f/--file` flags.
- Outputs clean ASCII summary tables or structured JSON for SIEM forwarding.
- Handles missing files, malformed log lines, and permission errors gracefully.

### Usage
```bash
# Analyze standard Fedora secure log with default threshold (5)
python3 scripts/log_analyzer.py --file /var/log/secure

# Custom threshold with JSON export
python3 scripts/log_analyzer.py sample_auth.log --threshold 3 --spray-threshold 3 --json

# Save report to a file
python3 scripts/log_analyzer.py -f sample_auth.log --threshold 5 --output report.json
```

---

## 2. File Integrity Monitor (`integrity_monitor.py`)

### Features
- Computes chunked SHA-256 cryptographic hashes for directory files.
- Generates reproducible JSON baseline snapshots containing hash, size, and UTC timestamp.
- Detects created, modified, and deleted files against the baseline.
- Safely handles filesystem exceptions, unreadable files, and broken symlinks.
- Returns non-zero exit codes upon detecting unauthorized modifications.

### Usage
```bash
# Step 1: Initialize baseline snapshot
python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --init --baseline /tmp/baseline.json

# Step 2: Compare directory state against baseline
python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --check --baseline /tmp/baseline.json

# Output as JSON for integration with alerting webhooks
python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --check --baseline /tmp/baseline.json --json
```

---

## 3. Environment Health Check (`health_check.sh`)

### Features
- Inspects essential binaries (`python3`, `git`, `curl`, container runtimes).
- Assesses container engine state (`docker` / `podman` daemon responsiveness).
- Verifies host memory capacity (warns if < 2048 MB free for Wazuh).
- Evaluates disk utilization on the working partition.
- Probes local homelab ports (`3000`, `1514`, `55000`, `443`).

### Usage
```bash
bash scripts/health_check.sh
```
