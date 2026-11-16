# Scenario 01: SSH Brute-Force & Authentication Log Analysis

## 1. Scenario Objective
Simulate and detect unauthorized OpenSSH authentication events against Linux endpoints. This scenario demonstrates both vertical brute-force dictionary attacks and horizontal password spraying, distinguishing malicious access attempts from benign operational noise without requiring root privileges or external infrastructure.

- **MITRE ATT&CK Mapping**:
  - [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/) (Vertical Brute Force)
  - [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/) (Horizontal Spray)
  - [TA0001 - Initial Access](https://attack.mitre.org/tactics/TA0001/) (Valid Accounts)
- **Target**: Linux OpenSSH Daemon (`sshd`)
- **Telemetry Sources**:
  - Live VM Mode: `/var/log/secure` (Fedora/RHEL) or `/var/log/auth.log` (Debian/Ubuntu)
  - Free Online Mode: `scenarios/01-ssh-bruteforce/sample_auth.log` (RFC 5737 simulated data)
- **Primary Detection Mechanisms**:
  - Python Automation: `scripts/log_analyzer.py` with multi-vector anomaly correlation
  - SIEM / XDR: Wazuh Rules `5710` (single failure), `100001` (frequency threshold), and active response

---

## 2. Tools Involved
- **Analysis Engine**: `scripts/log_analyzer.py` (Python 3.10+)
- **Codespaces Demonstration**: `scenarios/01-ssh-bruteforce/run_demo.sh`
- **Simulated Dataset**: `scenarios/01-ssh-bruteforce/sample_auth.log` (RFC 5737 compliant)
- **Live Simulation Script**: `scenarios/01-ssh-bruteforce/simulation.sh` (active network testing for dedicated VMs)
- **Export Destination**: `evidence/alert-exports/ssh_bruteforce_report.json`

---

## 3. Safety Notice & Scoping
> [!NOTE]
> All authentication events in `sample_auth.log` use documentation-reserved IP addresses (RFC 5737: `198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24` and RFC 1918: `192.168.1.0/24`). No live credentials, production passwords, or external network calls are used. The demonstration runs 100% unprivileged in GitHub Codespaces.

---

## 4. Execution Workflows

### Mode A: Free Online Mode (GitHub Codespaces / Offline Container)

#### 1. Single-Command Reproducible Demonstration
```bash
bash scenarios/01-ssh-bruteforce/run_demo.sh
```

#### 2. Manual CLI Analysis
```bash
# 1. Standard volumetric brute-force analysis (threshold: 5)
python3 scripts/log_analyzer.py -f scenarios/01-ssh-bruteforce/sample_auth.log --threshold 5

# 2. Horizontal password spraying detection (spray threshold: 3)
python3 scripts/log_analyzer.py -f scenarios/01-ssh-bruteforce/sample_auth.log --threshold 10 --spray-threshold 3

# 3. Export structured JSON forensic report
python3 scripts/log_analyzer.py -f scenarios/01-ssh-bruteforce/sample_auth.log --threshold 5 --json -o evidence/alert-exports/ssh_bruteforce_report.json
```

---

### Mode B: Dedicated Linux Host / Local VM Mode (Live Attack Simulation)

#### 1. Verify Target Connectivity
```bash
nc -zv 127.0.0.1 22
```

#### 2. Run Live Attack Simulation
```bash
bash scenarios/01-ssh-bruteforce/simulation.sh --target 127.0.0.1 --port 22 --attempts 8
```

#### 3. Analyze Live Host Syslog
```bash
python3 scripts/log_analyzer.py --file /var/log/secure --threshold 5
```

---

## 5. Detection Logic & Threshold Matrix

The analyzer evaluates three independent defensive rules:

1. **`SSH_BRUTE_FORCE`**: Triggered when `total_failures >= threshold` (default: 5).
2. **`PASSWORD_SPRAYING`**: Triggered when `len(targeted_users) >= spray_threshold` (default: 3) and `total_failures >= spray_threshold`.
3. **`SUCCESS_AFTER_FAILURES`**: Triggered when a source IP experiences $\ge$ `repeat_failure_threshold` (default: 2) failed attempts followed by an accepted login. **Evaluated independently of the volumetric threshold.**

| Source IP | Failures | Success | Detections at Threshold 5 | Detections at Threshold 10 | Threat Classification |
|---|---|---|---|---|---|
| `198.51.100.10` | 12 | 0 | `SSH_BRUTE_FORCE` | `SSH_BRUTE_FORCE` | Vertical Brute Force on `admin`/`root` |
| `203.0.113.45` | 6 | 0 | `SSH_BRUTE_FORCE`, `PASSWORD_SPRAYING` | `PASSWORD_SPRAYING` | Horizontal Password Spray across 6 accounts |
| `198.51.100.77` | 5 | 1 | `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` | `SUCCESS_AFTER_FAILURES` | **Critical Host Compromise** |
| `192.0.2.80` | 4 | 0 | None (Filtered) | None (Filtered) | Sub-threshold service attempt (`postgres`) |
| `192.168.1.99` | 1 | 1 | None (Suppressed) | None (Suppressed) | Benign single user typo (`dev_alice`) |
| `192.168.1.50` | 0 | 1 | None (Suppressed) | None (Suppressed) | Benign publickey login (`sysadmin`) |
