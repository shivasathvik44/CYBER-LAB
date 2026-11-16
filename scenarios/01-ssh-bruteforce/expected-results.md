# Scenario 01: Expected Results & Telemetry Analysis

This document describes the expected telemetry signatures, SIEM alert outputs, and Python analyzer results for both live simulation and offline analysis.

---

## 1. Live Simulation Mode (Dedicated VM / Endpoint)

### Raw Syslog Telemetry
When `simulation.sh` runs against OpenSSH, each attempt generates a failure record in `/var/log/secure` or `/var/log/auth.log`:

```text
Nov 14 12:01:05 fedora-endpoint sshd[28412]: Failed password for invalid user lab_test_user from 172.20.0.99 port 54312 ssh2
Nov 14 12:01:06 fedora-endpoint sshd[28412]: Connection closed by invalid user lab_test_user 172.20.0.99 port 54312 [preauth]
Nov 14 12:01:07 fedora-endpoint sshd[28415]: Failed password for invalid user lab_test_user from 172.20.0.99 port 54314 ssh2
```

### Wazuh SIEM Alerts
- **Individual Failure Alert (Rule `5710`, Level 5)**: `sshd: Attempt to login using a non-existent user` or `sshd: authentication failed.`
- **Correlated Brute-Force Alert (Rule `100001`, Level 10)**: `Homelab: High frequency SSH authentication failures from single IP (Possible Brute-Force)` (triggers when $\ge 6$ failures occur within 120s from identical IP).

---

## 2. Offline Analysis Mode (GitHub Codespaces / Sample Log)

- **Log Source**: `scenarios/01-ssh-bruteforce/sample_auth.log`
- **Total Lines**: 47
- **Total Failures in File**: 30
- **Total Successes in File**: 3

### Detection Results Matrix

| Source IP Address | Failures | Successes | Expected Detection Tags | Threat Classification |
|---|---|---|---|---|
| `198.51.100.10` | 12 | 0 | `SSH_BRUTE_FORCE` | High-frequency dictionary attack on `admin` & `root` |
| `203.0.113.45` | 6 | 0 | `SSH_BRUTE_FORCE`, `PASSWORD_SPRAYING` | Tested 6 distinct usernames (1 failure per user) |
| `198.51.100.77` | 5 | 1 | `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` | **CRITICAL COMPROMISE**: Credential cracked on `ubuntu` |
| `192.0.2.80` | 4 | 0 | None at default threshold 5 (`SSH_BRUTE_FORCE` at threshold 3) | Target `postgres` service account |
| `192.168.1.99` | 1 | 1 | None (Suppressed benign typo) | Benign internal developer typo (`dev_alice`) |
| `192.168.1.50` | 0 | 1 | None (Clean publickey login) | Benign sysadmin login |
| `192.0.2.140` | 2 | 0 | None (Below threshold) | Low-volume reconnaissance |

---

## 3. Threshold Tuning Matrix

| Metric | Threshold = 3 | Threshold = 5 (Default) | Threshold = 10 |
|---|---|---|---|
| **Total Suspicious IPs Flagged** | **4** | **3** | **3** |
| `198.51.100.10` (12 failures) | `SSH_BRUTE_FORCE` | `SSH_BRUTE_FORCE` | `SSH_BRUTE_FORCE` |
| `203.0.113.45` (6 user spray) | `SSH_BRUTE_FORCE`, `PASSWORD_SPRAYING` | `SSH_BRUTE_FORCE`, `PASSWORD_SPRAYING` | `PASSWORD_SPRAYING` (Volume < 10) |
| `198.51.100.77` (Compromise) | `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` | `SSH_BRUTE_FORCE`, `SUCCESS_AFTER_FAILURES` | `SUCCESS_AFTER_FAILURES` (Volume < 10) |
| `192.0.2.80` (4 failures) | `SSH_BRUTE_FORCE` | Filtered (0 tags) | Filtered (0 tags) |
| **Compromise Warnings** | 1 (`198.51.100.77`) | 1 (`198.51.100.77`) | 1 (`198.51.100.77`) |
| **Spray Campaigns Found** | 1 (`203.0.113.45`) | 1 (`203.0.113.45`) | 1 (`203.0.113.45`) |

---

## 4. Expected JSON Output Structure
Export destination: `evidence/alert-exports/ssh_bruteforce_report.json`
- `metadata.total_lines_processed`: 47
- `metadata.total_failures_detected`: 30
- `metadata.total_successes_detected`: 1
- `metadata.suspicious_ip_count`: 3 (at default threshold 5)
- `metadata.compromise_warnings_count`: 1
- `metadata.password_spray_count`: 1
- `metadata.repeat_failure_threshold`: 2
