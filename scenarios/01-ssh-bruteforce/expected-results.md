# Scenario 01: Expected Results & Telemetry Analysis

This document describes the expected telemetry signatures and alert outputs when executing the SSH brute-force simulation.

---

## 1. Expected Raw Telemetry

When `simulation.sh` runs against an OpenSSH daemon, each attempt generates a failure record in `/var/log/secure` (Fedora/RHEL) or `/var/log/auth.log` (Debian/Ubuntu):

```text
Nov 14 12:01:05 fedora-endpoint sshd[28412]: Failed password for invalid user lab_test_user from 172.20.0.99 port 54312 ssh2
Nov 14 12:01:06 fedora-endpoint sshd[28412]: Connection closed by invalid user lab_test_user 172.20.0.99 port 54312 [preauth]
Nov 14 12:01:07 fedora-endpoint sshd[28415]: Failed password for invalid user lab_test_user from 172.20.0.99 port 54314 ssh2
```

---

## 2. Expected Wazuh SIEM Alerts

### Individual Failure Alert (Rule `5710`)
- **Severity Level**: 5
- **Rule Description**: `sshd: Attempt to login using a non-existent user` or `sshd: authentication failed.`
- **Decoded Fields**:
  - `srcip`: `172.20.0.99`
  - `dstuser`: `lab_test_user`

### Correlated Brute-Force Alert (Rule `100001` or `5712`)
- **Severity Level**: 10
- **Rule Description**: `Homelab: High frequency SSH authentication failures from single IP (Possible Brute-Force)`
- **Condition**: Triggers when >= 6 failures occur within a 120-second sliding window from the identical source IP.

---

## 3. Log Analyzer Output Verification

Running `scripts/log_analyzer.py` against the log file produces:

```text
================================================================================
Linux Authentication Log Analyzer - Summary Report
================================================================================
Monitored Log File : /var/log/secure
Threshold          : 5 failed attempts
Total Log Lines    : 450
Failed Attempts    : 6
================================================================================
SUSPICIOUS SOURCE IPS (FAILED ATTEMPTS >= 5):
--------------------------------------------------------------------------------
Source IP        Failed Attempts   Targeted Accounts
172.20.0.99      6                 lab_test_user (6)
================================================================================
```

---

## 4. Verification Checklist
- [ ] Raw failure lines observed in `/var/log/secure`.
- [ ] Wazuh manager logs show alert rule `5710` firing.
- [ ] Wazuh alert rule `100001` fires after the 6th attempt.
- [ ] Log analyzer detects the IP and displays the formatted summary.
