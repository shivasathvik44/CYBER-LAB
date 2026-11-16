# Cybersecurity Homelab - Experiment Execution Log

Use this document to systematically record the results of your defensive security experiments, attack simulations, and forensic investigations. Keeping detailed engineering logs provides concrete, portfolio-ready evidence for cybersecurity internship interviews.

---

## Blank Experiment Log Template

Copy and paste the template below for each new experiment.

```markdown
# Experiment Log #[ID]: [Experiment Title]

## 1. Overview
- **Date & Time (UTC)**: YYYY-MM-DD HH:MM:SS
- **Analyst Name**: Shiva Sathvik
- **Environment**: [e.g., GitHub Codespaces (Linux 6.x container) / Fedora VM]
- **Target Component**: [e.g., Monitored Directory / SSH Daemon / Web App]
- **Objective**: [1-2 sentences on what you set out to test or detect]

## 2. MITRE ATT&CK Mapping
- **Tactic**: [e.g., Impact (TA0040) / Credential Access (TA0006)]
- **Technique ID & Name**: [e.g., T1565.001 Stored Data Manipulation]

## 3. Commands Executed
```bash
# Step 1: Baseline or preparation command
[command here]

# Step 2: Attack simulation or trigger command
[command here]

# Step 3: Detection or triage command
[command here]
```

## 4. Expected Results vs. Actual Results

| Test Step | Expected Outcome | Actual Outcome | Status |
|---|---|---|---|
| Step 1 | [e.g., Baseline records 3 files] | [e.g., Exactly 3 files hashed] | PASS / FAIL |
| Step 2 | [e.g., Tampering detected with 3 anomalies] | [e.g., 1 created, 1 modified, 1 deleted] | PASS / FAIL |
| Step 3 | [e.g., Output saved to JSON] | [e.g., Valid JSON written] | PASS / FAIL |

## 5. Evidence & Forensic Artifacts
- **Terminal Output Snippet**:
```text
[Paste terminal output here]
```
- **Generated Report Path**: `evidence/alert-exports/[filename].json`
- **Screenshot / Visualization Reference**: `evidence/screenshots/[image.png]`

## 6. Key Findings & Analysis
- What specifically triggered the detection?
- Were there false positives or unexpected behaviors?
- How did the tool respond to edge cases?

## 7. Lessons Learned & Defensive Recommendations
- **Defensive Control**: [e.g., How would an enterprise prevent or mitigate this?]
- **Detection Engineering**: [e.g., How would you tune alerting thresholds to reduce alert fatigue?]
- **Analyst Reflection**: [e.g., What did you learn from this exercise?]
```

---

## Completed Sample Entry: File Integrity Monitoring (FIM)

Use this completed sample as a reference for your own experiment entries.

# Experiment Log #001: File Integrity Monitoring & Tampering Detection

## 1. Overview
- **Date & Time (UTC)**: 2026-11-14 16:56:45 UTC
- **Analyst Name**: Shiva Sathvik
- **Environment**: GitHub Codespaces (Ubuntu 22.04 / Python 3.11 Container)
- **Target Component**: User-Space Testbed (`.fim_demo_lab`)
- **Objective**: Verify that cryptographic SHA-256 baseline hashing detects unauthorized file modification, backdoor injection, file deletion, and handles inaccessible files safely without root privileges.

## 2. MITRE ATT&CK Mapping
- **Tactic**: Impact ([TA0040](https://attack.mitre.org/tactics/TA0040/)) & Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
- **Technique ID & Name**: [T1565.001 - Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/) & [T1070 - Indicator Removal on Host](https://attack.mitre.org/techniques/T1070/)

## 3. Commands Executed
```bash
# 1. Execute full FIM demonstration
bash scenarios/02-file-integrity/run_demo.sh

# 2. Run unit tests
pytest -v tests/test_integrity_monitor.py
```

## 4. Expected Results vs. Actual Results

| Test Step | Expected Outcome | Actual Outcome | Status |
|---|---|---|---|
| Step 1: Sandbox Initialization | 3 seed files created in testbed | Files created: `config.ini`, `policy.json`, `auth_helper.py` | PASS |
| Step 2: Baseline Generation | SHA-256 hashes generated for all 3 files | Baseline JSON written with 3 records | PASS |
| Step 3: Clean State Check | 0 anomalies detected; exit code 0 | `Status: INTEGRITY VERIFIED (CLEAN)`; exit code 0 | PASS |
| Step 4: Modification Detection | Tampering in `config.ini` flagged | `[MODIFIED] config.ini` with expected vs actual hash | PASS |
| Step 5: Creation Detection | Injected `backdoor.sh` flagged | `[CREATED] backdoor.sh` detected | PASS |
| Step 6: Deletion Detection | Missing `policy.json` flagged | `[DELETED] policy.json` detected | PASS |
| Step 7: Inaccessible File Safety | Unreadable file skipped with warning, no crash | Warning printed, listed under `Inaccessible Files: 1` | PASS |
| Step 8: Corrupt Baseline Catch | Invalid JSON handled gracefully with error code 1 | Safely caught with clean error message; no unhandled exception | PASS |
| Step 9: Forensic JSON Export | Valid JSON written to `evidence/alert-exports/` | Report saved to `evidence/alert-exports/fim_demo_report.json` | PASS |

## 5. Evidence & Forensic Artifacts
- **Terminal Output Snippet**:
```text
CYBERSECURITY HOMELAB - FILE INTEGRITY MONITOR REPORT
================================================================================
Monitored Directory : .../.fim_demo_lab
Baseline File       : .../.fim_demo_baseline.json
Status              : ⚠️  TAMPERING DETECTED
--------------------------------------------------------------------------------
Created Files       : 1
Modified Files      : 1
Deleted Files       : 1
Unchanged Files     : 1
Inaccessible Files  : 1
================================================================================

[+] NEW / CREATED FILES:
    + backdoor.sh (SHA-256: 2e3d25e589b74ddb...)

[!] MODIFIED FILES:
    ! config.ini
        Expected: aa2c0bd12d680ce2c9bd319475e1cc0f0893e7ff675bf9edbcaf36d20f07d170
        Current : d3cbe753a3da523ffce4df07434393a5bc495266656fa4d02233ca2f130a2c4c

[-] DELETED FILES:
    - policy.json (Expected SHA-256: 1aae3db7a77002d5...)
```
- **Generated Report Path**: `evidence/alert-exports/fim_demo_report.json`

## 6. Key Findings & Analysis
1. **Cryptographic Sensitivity**: Modifying a single character inside `config.ini` completely altered the SHA-256 digest (`aa2c0bd1...` -> `d3cbe753...`), demonstrating the avalanche effect of cryptographic hashing.
2. **Safety Architecture**: Storing the baseline snapshot outside the monitored directory prevents self-referential false positives.
3. **Resilience**: File permission errors (`chmod 000`) were handled without halting the audit process, ensuring partial filesystem errors do not blind the entire monitoring suite.

## 7. Lessons Learned & Defensive Recommendations
- **Defensive Control**: In enterprise environments, FIM alerts should trigger automated immutable snapshots and alert SOAR playbooks for instant containment.
- **Detection Engineering**: To reduce noise, static configuration files should be monitored with high severity, while high-churn log files should be excluded via ignore rules.
- **Analyst Reflection**: Practiced building and verifying defensive Python tooling entirely in a free online cloud environment with zero infrastructure cost.

---

## Completed Sample Entry: SSH Brute-Force & Log Analysis

# Experiment Log #002: SSH Brute-Force Detection & Authentication Log Analysis

## 1. Overview
- **Date & Time (UTC)**: 2026-11-16 18:30:00 UTC
- **Analyst Name**: Shiva Sathvik
- **Environment**: GitHub Codespaces (Ubuntu 22.04 / Python 3.11 Container)
- **Target Component**: OpenSSH Authentication Log Analyzer (`scripts/log_analyzer.py`)
- **Objective**: Detect vertical SSH brute-force attacks, horizontal password spraying, and critical host compromise patterns (`SUCCESS_AFTER_FAILURES`) from simulated RFC 5737 log data without root privileges.

## 2. MITRE ATT&CK Mapping
- **Tactic**: Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/)) & Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/))
- **Technique ID & Name**: [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/) & [T1110.003 - Password Spraying](https://attack.mitre.org/techniques/T1110/003/)

## 3. Commands Executed
```bash
# 1. Execute complete reproducible demonstration
bash scenarios/01-ssh-bruteforce/run_demo.sh

# 2. Run unit tests
python3 -m unittest discover -s tests -v

# 3. Analyze specific scenario with custom threshold
python3 scripts/log_analyzer.py -f scenarios/01-ssh-bruteforce/sample_auth.log --threshold 5 --spray-threshold 3
```

## 4. Expected Results vs. Actual Results

| Test Step | Expected Outcome | Actual Outcome | Status |
|---|---|---|---|
| Step 1: Log Parsing | 47 lines processed, 30 failures, 1 accepted login | 47 lines parsed, 30 failures detected, 1 success | PASS |
| Step 2: Brute-Force Detection | Flag `198.51.100.10` with 12 failures against `admin` & `root` | Flagged `198.51.100.10` with tag `SSH_BRUTE_FORCE` | PASS |
| Step 3: Password Spraying | Flag `203.0.113.45` targeting 6 distinct usernames | Flagged with tag `PASSWORD_SPRAYING` | PASS |
| Step 4: Compromise Detection | Flag `198.51.100.77` with 5 failures followed by login | Flagged with critical alert `SUCCESS_AFTER_FAILURES` | PASS |
| Step 5: Threshold Tuning | Evaluate thresholds 3, 5, 10; decoupled compromise alert | Threshold 3 flags 4 IPs, 5 flags 3 IPs, 10 flags 3 IPs | PASS |
| Step 6: JSON Export | Structured JSON written to `evidence/alert-exports/` | Valid JSON written to `ssh_bruteforce_report.json` | PASS |
| Step 7: Offline Non-Root Safety | 0 modifications to `/var/log/auth.log`, runs as standard user | Executed fully unprivileged with 0 system mutations | PASS |

## 5. Evidence & Forensic Artifacts
- **Terminal Output Snippet**:
```text
Source IP          Failures   Success   First Seen       Detections
------------------------------------------------------------------------------------
198.51.100.10      12         0         Nov 16 09:00:01  SSH_BRUTE_FORCE
203.0.113.45       6          0         Nov 16 09:15:00  SSH_BRUTE_FORCE, PASSWORD_SPRAYING
198.51.100.77      5          1         Nov 16 10:20:01  SSH_BRUTE_FORCE, SUCCESS_AFTER_FAILURES
------------------------------------------------------------------------------------
DETECTION DETAILS & TARGETED ACCOUNTS:

[*] Source IP: 198.51.100.77
    - Failures : 5 | Successes: 1
    - Targeted Accounts : ubuntu (5)
    - Authenticated As  : ubuntu (1)
    - [DETECTED] Failed attempts (5) reached threshold (5)
    - [CRITICAL COMPROMISE] CRITICAL: Successful login for account(s) [ubuntu] following 5 failed attempts
```
- **Generated Report Path**: `evidence/alert-exports/ssh_bruteforce_report.json`

## 6. Key Findings & Analysis
1. **Vertical vs. Horizontal Signatures**: Vertical brute-force attacks generate high failure counts against a few high-value accounts (`admin`, `root`), whereas password spraying stays below volume thresholds by targeting numerous users horizontally (`operator`, `support`, `backup`, `deploy`, `testuser`, `manager`). Spraying detection requires tracking distinct targeted usernames rather than total failure counts alone.
2. **Threshold Sensitivity**: A threshold of 3 produces alerts on minor user mistakes (`192.0.2.80` with 4 failures), while a threshold of 10 misses an attacker who successfully breaches an account on the 6th attempt (`198.51.100.77`).
3. **High-Fidelity Compromise Indicator**: Correlating failure timestamps with subsequent successful logins from the same source IP provides high-confidence evidence of compromised credentials requiring urgent incident response.

## 7. Lessons Learned & Defensive Recommendations
- **Defensive Control**: Disable password authentication in OpenSSH configuration (`PasswordAuthentication no`) to eliminate password guessing vectors entirely.
- **Detection Engineering**: Decouple password spraying alerts (username cardinality) from volumetric brute-force thresholds (failure count).
- **Incident Response Playbook**: When `SUCCESS_AFTER_FAILURES` fires, immediately terminate the active SSH session, revoke keys, rotate credentials, and inspect process trees for spawned interactive shells or command execution.

