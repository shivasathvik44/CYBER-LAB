# Technical Learnings & SOC Competency Reflection

This document captures the technical, operational, and architectural insights gained throughout the design, implementation, and operation of the **Cybersecurity Homelab**.

---

## 1. Core Competencies Developed

### 1.1 SIEM Operations & Detection Engineering
- **Rule Hierarchy & Correlation**: Learned how Wazuh evaluates incoming log events through pre-decoders, decoders, and multi-stage hierarchical rules (`if_sid`, `if_matched_sid`).
- **Threshold & Anomaly Detection**: Authored time-bounded sliding window rules (e.g. 6 failures within 120 seconds) to separate brute-force attacks from routine human password typos.
- **Index Lifecycle & Querying**: Understood OpenSearch / Elasticsearch document storage for high-volume telemetry ingestion and dashboard visualization.

### 1.2 Linux Endpoint Telemetry & Kernel Auditing
- **Syscall Visibility via `auditd`**: Configured kernel-level event tracking for `execve` and `execveat` syscalls to expose command executions, parent-child process lineages, and obfuscated commands.
- **Authentication Subsystem (PAM)**: Analyzed differences in authentication logging across Linux distributions (`/var/log/secure` vs `/var/log/auth.log`) and mastered regex extraction of remote host addresses (`rhost`).
- **File Integrity Monitoring (FIM)**: Understood cryptographic hash tracking (SHA-256) versus inode metadata tracking for detecting file tampering and persistence establishment.

### 1.3 Network Security Monitoring & Deep Packet Inspection
- **Suricata NIDS Signatures**: Wrote Snort/Suricata syntax rules matching TCP flags (`flags:S,12`), packet frequencies, and HTTP URI application-layer strings (`UNION SELECT`, directory traversal).
- **Structured Network Telemetry**: Processed Suricata `eve.json` records to correlate external network probes with downstream endpoint audit logs.

### 1.4 Security Automation & Tooling
- **Defensive Python Development**: Built modular, safe, standalone tools (`log_analyzer.py` and `integrity_monitor.py`) using Python standard libraries for rapid incident triage.
- **Continuous Integration**: Configured automated GitHub Actions workflows with `pytest` and `ruff` to enforce code quality, exception safety, and regression prevention.

---

## 2. Engineering Tradeoffs & Architectural Decisions

| Decision | Chosen Approach | Alternative Considered | Rationale |
|---|---|---|---|
| **Workload Isolation** | Docker bridge networks | Multi-node VMware / Proxmox | Drastically reduced RAM/CPU footprint while preserving network and port isolation on a single developer workstation. |
| **Vulnerable Target** | OWASP Juice Shop | Metasploitable / DVWA | Modern JavaScript/Node.js architecture reflecting realistic cloud-native web threats. |
| **Telemetry Ingestion** | Native Wazuh Agent | Syslog over UDP (514) | Agent provides encrypted TLS delivery, spooling queues during network outages, and local syscheck hash computation. |
| **FIM Implementation** | Wazuh Syscheck + Custom Python Script | Inotify standalone daemon | Wazuh provides centralized alerts; Python script provides standalone, dependency-free verification for offline compliance audits. |

---

## 3. Interview Portfolio Talking Points

When presenting this project during cybersecurity and SOC analyst interviews, key themes to emphasize include:
1. **End-to-End Visibility**: Demonstrating how an adversary action (e.g. SSH brute force or web injection) propagates from raw packets and kernel syscalls into normalized SIEM alerts.
2. **Defensive Rigor**: Explaining the difference between alert noise and high-fidelity alerts through threshold tuning and whitelist filters.
3. **Reproducibility & Safety**: Highlighting strict network scoping rules, non-destructive simulation fixtures, and automated testing pipelines.
4. **Structured Incident Response**: Walking through a real simulated incident from initial alert to containment, eradication, and post-incident report authoring following NIST SP 800-61.

---

## 4. Cross-Links
- [Architecture Deep Dive](ARCHITECTURE.md)
- [Attack Scenarios Matrix](ATTACK-SCENARIOS.md)
- [Incident Response SOP](INCIDENT-RESPONSE.md)
- [Detection Rules Specification](DETECTION-RULES.md)
