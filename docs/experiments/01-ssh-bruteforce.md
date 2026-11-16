# Experiment 01: SSH Brute-Force & Authentication Log Analysis

**Experiment ID:** EXP-002 (Scenario 01)  
**Date:** November 16, 2026  
**Investigator / Analyst:** shivasathvik44  
**Classification:** Defensive Offline Log Analysis / SOC Triage  
**Status:** Completed & Verified ✅  
**Target Environment:** GitHub Codespaces / Unprivileged Linux Container  

---

## 1. Executive Summary & Objective

In this defensive exercise, we analyze OpenSSH authentication event streams to identify adversary access patterns, brute-force attempts, credential stuffing/spraying, and unauthorized host compromises. The analysis is conducted entirely offline against simulated syslog files complying with RFC 5737 (`198.51.100.0/24`, `203.0.113.0/24`, `192.0.2.0/24`) and RFC 1918 (`192.168.1.0/24`) without requiring root access, virtual machines, or external internet access.

### Core Objectives
1. **High-Volume Brute Force**: Detect automated vertical dictionary attacks attempting multiple passwords against administrative accounts (`root`, `admin`).
2. **Horizontal Password Spraying**: Detect multi-account attacks where a single adversary source tests passwords across numerous distinct accounts (`operator`, `support`, `backup`, `deploy`, `testuser`, `manager`).
3. **Independent Critical Compromise Warning (`SUCCESS_AFTER_FAILURES`)**: Flag instances where an IP address experiences repeated failed logins ($\ge 2$) followed by a successful authentication—a hallmark of cracked or guessed credentials. Crucially, this detection operates independently of the volumetric brute-force threshold.
4. **Threshold Tuning Evaluation**: Compare detection sensitivity and false-positive / false-negative trade-offs across thresholds of **3**, **5**, and **10** failed attempts.
5. **SIEM / SOC Integration**: Export structured JSON telemetry into `evidence/alert-exports/` for automated pipeline ingestion.

---

## 2. Tools & Architecture

| Component | Technology | Purpose |
|---|---|---|
| **Log Analyzer Engine** | Python 3 (`scripts/log_analyzer.py`) | Regex parsing, state aggregation, multi-vector anomaly correlation |
| **Demo Orchestrator** | Bash (`scenarios/01-ssh-bruteforce/run_demo.sh`) | 7-step automated verification pipeline |
| **Simulated Dataset** | Plaintext Syslog (`scenarios/01-ssh-bruteforce/sample_auth.log`) | RFC 5737 compliant test events without PII or live credentials |
| **Runtime Environment** | GitHub Codespaces / Dev Container | 100% free unprivileged container execution |

---

## 3. Simulated Attack Data Breakdown

The simulated log file `scenarios/01-ssh-bruteforce/sample_auth.log` contains 47 log lines modeling both benign background operational noise and three distinct attack vectors:

| Source IP Address | IP Category | Failure Count | Success Count | Targeted Accounts | Threat Classification |
|---|---|---|---|---|---|
| `192.168.1.50` | RFC 1918 (Internal) | 0 | 1 | `sysadmin` | **Benign**: Standard public-key login |
| `192.168.1.99` | RFC 1918 (Internal) | 1 | 1 | `dev_alice` | **Benign User Typo**: Single typo followed by valid password (Suppressed) |
| `198.51.100.10` | RFC 5737 (External) | 12 | 0 | `admin` (6), `root` (6) | **Vertical High-Volume Brute Force** |
| `203.0.113.45` | RFC 5737 (External) | 6 | 0 | 6 distinct usernames | **Horizontal Password Spraying Campaign** |
| `192.0.2.80` | RFC 5737 (External) | 4 | 0 | `postgres` (4) | Service account password guessing |
| `198.51.100.77` | RFC 5737 (External) | 5 | 1 | `ubuntu` (5 failures, 1 success) | **Critical Host Compromise** (`SUCCESS_AFTER_FAILURES`) |
| `192.0.2.140` | RFC 5737 (External) | 2 | 0 | `guest` (2) | Low-volume reconnaissance |
| `N/A` | System noise | - | - | - | Sudo commands, CRON jobs, preauth drops |

> [!NOTE]
> All IP addresses are strictly documentation-reserved ranges. No real personal credentials or production logs are involved.

---

## 4. Detection Logic & Parsing Mechanisms

### OpenSSH Log Parsing Patterns
```python
# Failed authentication attempts (password, publickey, invalid user)
FAILED_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w\.\-]+)\s+sshd\[\d+\]:\s+Failed\s+(?P<method>password|publickey|none)\s+"
    r"for\s+(?:invalid\s+user\s+)?(?P<user>[^\s]+)\s+from\s+(?P<ip>[\d\.]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)

# Successful authentication attempts
ACCEPTED_AUTH_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[\w\.\-]+)\s+sshd\[\d+\]:\s+Accepted\s+(?P<method>password|publickey|keyboard-interactive)\s+"
    r"for\s+(?P<user>[^\s]+)\s+from\s+(?P<ip>[\d\.]+)\s+port\s+(?P<port>\d+)",
    re.IGNORECASE,
)
```

### Anomaly Classification Rules (Decoupled & Independent)
1. **`SSH_BRUTE_FORCE`**: Triggered when `total_failures >= threshold` (default: 5).
2. **`PASSWORD_SPRAYING`**: Triggered when `len(targeted_users) >= spray_threshold` (default: 3) and `total_failures >= spray_threshold`. Operates independently of volumetric thresholds.
3. **`SUCCESS_AFTER_FAILURES`**: Triggered when `success_after_failure is True` and `total_failures >= repeat_failure_threshold` (default: 2). **Decoupled from the brute-force threshold** so that a compromised host is never missed due to strict volumetric filters. An isolated single typo (1 failure before success) is suppressed.

---

## 5. Reproduction & Execution Instructions

Run the single-command reproducible demonstration inside GitHub Codespaces:

```bash
# Option 1: Run the scenario demo directly
bash scenarios/01-ssh-bruteforce/run_demo.sh

# Option 2: Run via the scripts root wrapper
bash scripts/run_ssh_demo.sh

# Option 3: Manual execution of the Python engine
python3 scripts/log_analyzer.py -f scenarios/01-ssh-bruteforce/sample_auth.log --threshold 5
```

---

## 6. Threshold Tuning Analysis (3 vs 5 vs 10)

SOC analysts must balance threat detection against alert fatigue. We evaluated our analyzer across three threshold configurations:

| Metric | Threshold = 3 (Aggressive) | Threshold = 5 (Balanced) | Threshold = 10 (Strict Volume) |
|---|---|---|---|
| **Total Suspicious IPs Flagged** | **4** | **3** | **3** |
| **`198.51.100.10` (12 fails)** | ✅ `SSH_BRUTE_FORCE` | ✅ `SSH_BRUTE_FORCE` | ✅ `SSH_BRUTE_FORCE` |
| **`203.0.113.45` (6 user spray)** | ✅ `SSH_BRUTE_FORCE`, `PASSWORD_SPRAYING` | ✅ `SSH_BRUTE_FORCE`, `PASSWORD_SPRAYING` | ✅ `PASSWORD_SPRAYING` (Volume < 10, but Spray Caught) |
| **`198.51.100.77` (5 fails + login)** | ✅ `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` | ✅ `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` | ✅ `SUCCESS_AFTER_FAILURES` (Volume < 10, but Compromise Caught!) |
| **`192.0.2.80` (4 fails)** | ✅ `SSH_BRUTE_FORCE` | ❌ Suppressed (Filtered as noise) | ❌ Suppressed (Filtered as noise) |
| **Compromise Warnings** | **1** (`198.51.100.77`) | **1** (`198.51.100.77`) | **1** (`198.51.100.77`) |
| **Spray Campaigns** | **1** (`203.0.113.45`) | **1** (`203.0.113.45`) | **1** (`203.0.113.45`) |
| **False-Positive Risk** | **High**: Users with 3 mistyped passwords trigger volume alerts. | **Low**: Suppresses accidental typos; captures true attacks. | **Extremely Low**: Only catastrophic volumetric attacks surfaced. |
| **False-Negative Risk** | **Very Low**: Catches all unauthorized attempts. | **Very Low**: Catches all attacks; filters sub-threshold noise. | **Low**: Volumetric attacks filtered, but decoupled heuristics catch spray & compromise! |

### Analyst Conclusion on Thresholds:
> **Decoupled Detection Architecture**: In modern SOC engineering, high-severity compromise heuristics (`SUCCESS_AFTER_FAILURES`) and horizontal spray heuristics (`PASSWORD_SPRAYING`) must never be gated behind volumetric brute-force thresholds. By separating volumetric filtering (`--threshold`) from compromise sensitivity (`--repeat-threshold`), the SOC can raise the brute-force threshold to 10 or 20 to eliminate alert fatigue without blinding the security team to targeted credential cracking.

---

## 7. Sample Outputs

### Terminal Report Preview (Conservative Threshold = 10)
```text
====================================================================================
CYBERSECURITY HOMELAB - AUTHENTICATION LOG ANALYSIS REPORT
====================================================================================
Log Source Path       : scenarios/01-ssh-bruteforce/sample_auth.log
Threshold Filter      : >= 10 failed attempts
Spray Threshold       : >= 3 distinct targeted usernames
Compromise Threshold  : >= 2 failed attempts followed by login
Total Lines Processed : 47
Total Failed Logins   : 30
Suspicious IPs Flagged: 3
Compromise Warnings   : 1 (Successful login after repeated failures)
Spray Campaigns Found : 1
------------------------------------------------------------------------------------
Source IP          Failures   Success   First Seen       Detections
------------------------------------------------------------------------------------
198.51.100.10      12         0         Nov 16 09:00:01  SSH_BRUTE_FORCE
203.0.113.45       6          0         Nov 16 09:15:00  PASSWORD_SPRAYING
198.51.100.77      5          1         Nov 16 10:20:01  SUCCESS_AFTER_FAILURES
------------------------------------------------------------------------------------
DETECTION DETAILS & TARGETED ACCOUNTS:

[*] Source IP: 198.51.100.10
    - Failures : 12 | Successes: 0
    - Targeted Accounts : admin (6), root (6)
    - [DETECTED] Failed attempts (12) reached brute-force threshold (10)

[*] Source IP: 203.0.113.45
    - Failures : 6 | Successes: 0
    - Targeted Accounts : backup (1), deploy (1), manager (1), operator (1), support (1), testuser (1)
    - [DETECTED] Targeted 6 distinct usernames across 6 attempts (spray threshold: 3)

[*] Source IP: 198.51.100.77
    - Failures : 5 | Successes: 1
    - Targeted Accounts : ubuntu (5)
    - Authenticated As  : ubuntu (1)
    - [CRITICAL COMPROMISE] CRITICAL: Successful login for account(s) [ubuntu] following 5 failed attempts (repeated failure threshold: 2)
====================================================================================
```

### Structured JSON Report Preview (`evidence/alert-exports/ssh_bruteforce_report.json`)
```json
{
  "metadata": {
    "log_file": "scenarios/01-ssh-bruteforce/sample_auth.log",
    "threshold": 5,
    "spray_threshold": 3,
    "repeat_failure_threshold": 2,
    "total_lines_processed": 47,
    "total_failures_detected": 30,
    "total_successes_detected": 1,
    "suspicious_ip_count": 3,
    "compromise_warnings_count": 1,
    "password_spray_count": 1
  },
  "suspicious_ips": [
    {
      "source_ip": "198.51.100.77",
      "total_failures": 5,
      "targeted_users": {
        "ubuntu": 5
      },
      "first_seen": "Nov 16 10:20:01",
      "last_seen": "Nov 16 10:20:13",
      "total_successes": 1,
      "successful_users": {
        "ubuntu": 1
      },
      "success_after_failure": true,
      "password_spray": false,
      "detections": [
        "SSH_BRUTE_FORCE",
        "SUCCESS_AFTER_FAILURES"
      ],
      "detection_reasons": [
        "Failed attempts (5) reached brute-force threshold (5)",
        "CRITICAL: Successful login for account(s) [ubuntu] following 5 failed attempts (repeated failure threshold: 2)"
      ]
    }
  ]
}
```

---

## 8. SOC Remediation & Hardening Recommendations

1. **Enforce SSH Key Authentication**: Disable password authentication in `/etc/ssh/sshd_config`:
   ```text
   PasswordAuthentication no
   PermitRootLogin prohibit-password
   PubkeyAuthentication yes
   ```
2. **Deploy Active Response / Fail2ban**: Configure automated host-level banning of IP addresses exceeding 5 failed attempts within a 10-minute sliding window.
3. **Emergency Credential Rotation**: For any host exhibiting `SUCCESS_AFTER_FAILURES` on `ubuntu`, immediately revoke existing SSH keys, reset credentials, review authorized_keys, and inspect bash history for dropped persistence artifacts.
4. **Implement Multi-Factor Authentication (MFA)**: Require PAM-level TOTP/FIDO2 keys for SSH sessions accessing privileged accounts.

---

## 9. Verification & Automated Testing

All capabilities are validated via automated unit testing:

```bash
python3 -m unittest discover -s tests -v
```

Verified test coverage (27 tests) includes:
- Standard SSH failed password parsing
- PAM-level failure regex parsing
- Accepted password and publickey authentication parsing
- Sub-threshold failed logins
- High-volume brute force
- Password spraying across distinct usernames
- Success-after-failure detection at threshold 10
- Multi-IP aggregation
- Threshold variations (3 vs 5 vs 10)
- Empty log files and malformed/non-matching syslog noise
- Isolation and independence of all three detection thresholds
