# Security Attack Scenarios Matrix

This document provides a consolidated catalog of the five core attack scenarios implemented and documented within the **Cybersecurity Homelab**, mapped directly to the **MITRE ATT&CK** matrix.

---

## 1. Scenario Summary Matrix

| # | Scenario Title | MITRE ATT&CK Tactic | Technique ID | Primary Telemetry Source | Primary Detection Engine |
|---|---|---|---|---|---|
| **01** | [SSH Brute-Force](../scenarios/01-ssh-bruteforce/README.md) | Credential Access | [T1110.001](https://attack.mitre.org/techniques/T1110/001/) | `/var/log/secure` | Wazuh Rules `5710` & `100001` |
| **02** | [File Integrity Monitoring](../scenarios/02-file-integrity/README.md) | Impact / Defense Evasion | [T1565.001](https://attack.mitre.org/techniques/T1565/001/) | `syscheck` / Inode metadata | Wazuh Rule `550` & `integrity_monitor.py` |
| **03** | [Suspicious Process](../scenarios/03-suspicious-process/README.md) | Execution / Defense Evasion | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | `/var/log/audit/audit.log` | Linux Auditd & Wazuh Rule `100010` |
| **04** | [Web Application Attacks](../scenarios/04-web-attacks/README.md) | Initial Access / Injection | [T1190](https://attack.mitre.org/techniques/T1190/) | HTTP Access Logs & PCAP | Suricata SIDs `1000002` & `1000003` |
| **05** | [Network Scanning](../scenarios/05-network-scanning/README.md) | Discovery / Reconnaissance | [T1046](https://attack.mitre.org/techniques/T1046/) | Network Packets (SYN flags) | Suricata SID `1000001` |

---

## 2. Detailed Scenario Profiles

### Scenario 01: SSH Brute-Force Detection
- **Objective**: Simulate high-frequency SSH password guessing against the Linux endpoint to evaluate rate-based correlation rules.
- **Tools**: Bash simulation script (`simulation.sh`), OpenSSH daemon, `log_analyzer.py`.
- **Simulation**: Transmits repeated login attempts with invalid credentials against target port 22.
- **Expected Telemetry**: Burst of `Failed password for invalid user` lines in `/var/log/secure`.
- **Detection Method**: Wazuh threshold rule triggering on 6 failures within 120 seconds from a single IP.
- **Remediation**: Automatic IP ban via Fail2ban / Wazuh Active Response; enforce SSH keys and disable password auth.

### Scenario 02: File Integrity Monitoring (FIM)
- **Objective**: Detect unauthorized tampering, file creation, and deletion in a designated critical directory (`/tmp/homelab-fim-test`).
- **Tools**: `simulation.sh`, Wazuh Syscheck, `scripts/integrity_monitor.py`.
- **Simulation**: Modifies an application config, drops a shell script, and deletes a policy file.
- **Expected Telemetry**: Real-time hash comparison changes (SHA-256) and inode audit records.
- **Detection Method**: Wazuh Rules 550, 554, 553, and Python baseline diff reporting.
- **Remediation**: Restore verified copies from immutable backups; set immutable flag (`chattr +i`).

### Scenario 03: Suspicious Process Execution
- **Objective**: Detect unauthorized binary execution from world-writable directories and obfuscated command lines.
- **Tools**: `simulation.sh`, Linux Auditd, `ausearch`.
- **Simulation**: Drops and executes a script in `/tmp`, runs base64-encoded command, and probes loopback port 4444.
- **Expected Telemetry**: `SYSCALL` (syscall 59 `execve`) and `EXECVE` records with key `process_exec`.
- **Detection Method**: Auditd rule filter and Wazuh custom rule `100010`.
- **Remediation**: Terminate rogue PID, remount `/tmp` with `noexec` flag, and inspect parent process hierarchy.

### Scenario 04: Web Application Attack Detection
- **Objective**: Detect OWASP Top 10 exploits targeting the vulnerable OWASP Juice Shop container.
- **Tools**: `curl`, Burp Suite Community Edition, Suricata NIDS.
- **Simulation**: Sends SQL injection (`UNION SELECT`), Cross-Site Scripting (`<script>`), and directory traversal payloads.
- **Expected Telemetry**: HTTP GET/POST transaction logs and raw HTTP stream inspection.
- **Detection Method**: Suricata HTTP protocol signatures matching keywords and regex patterns.
- **Remediation**: Implement input sanitization, prepared statements, and Web Application Firewall (WAF) filtering.

### Scenario 05: Network Scanning & Reconnaissance
- **Objective**: Identify hostile network sweeps, port enumeration, and service fingerprinting.
- **Tools**: Nmap, Bash TCP socket probe, Suricata NIDS.
- **Simulation**: Initiates rapid TCP SYN sweeps across ports 20–100 against target IP.
- **Expected Telemetry**: High-frequency TCP SYN packets without completed handshakes.
- **Detection Method**: Suricata threshold alert `1000001` (`HOMELAB SCAN Potential Nmap SYN Sweep`).
- **Remediation**: Apply iptables `recent` or `hashlimit` modules to throttle or drop port sweeps.

---

## 3. Cross-Links
- [Detection Rules Specifications](DETECTION-RULES.md)
- [Incident Response Runbook](INCIDENT-RESPONSE.md)
- [Expected Results - SSH](../scenarios/01-ssh-bruteforce/expected-results.md)
- [Expected Results - FIM](../scenarios/02-file-integrity/expected-results.md)
- [Expected Results - Process](../scenarios/03-suspicious-process/expected-results.md)
- [Expected Results - Web](../scenarios/04-web-attacks/test-cases.md)
- [Expected Results - Network](../scenarios/05-network-scanning/expected-results.md)
