# Incident Response Standard Operating Procedure (SOP)

This document establishes the Standard Operating Procedures (SOPs) for triaging, investigating, containing, and recovering from security incidents detected within the **Cybersecurity Homelab**, structured according to the **NIST SP 800-61 Rev. 2** framework.

---

## 1. Incident Response Lifecycle Overview

```text
+--------------------------------------------------------------------------------+
|                        NIST SP 800-61 INCIDENT PHASES                          |
+--------------------------------------------------------------------------------+
|  1. PREPARATION   | Hardened baselines, logging daemons, audit rules, backups  |
|  2. IDENTIFICATION| SIEM alerts, NIDS signatures, log analyzer triggers        |
|  3. CONTAINMENT   | Network isolation, firewall drops, process termination     |
|  4. ERADICATION   | Removal of malware artifacts, backdoors, unauthorized keys |
|  5. RECOVERY      | Restoration from verified clean state, service validation  |
|  6. LESSONS LEARN | Incident report authoring, rule tuning, control updates    |
+--------------------------------------------------------------------------------+
```

---

## 2. Phase-by-Phase Operational Runbooks

### Phase 1: Preparation
- Maintain immutable backups of baseline system states.
- Ensure `auditd`, `wazuh-agent`, and `suricata` daemons are running and healthy.
- Validate script readiness: `bash scripts/health_check.sh`.

### Phase 2: Identification & Triage

#### Triage Runbook A: Authentication / Brute-Force Alert
1. **Verify Alert Validity**: Inspect source IP in Wazuh Dashboard.
2. **Execute Host Log Triage**:
   ```bash
   python3 scripts/log_analyzer.py --file /var/log/secure --threshold 5
   ```
3. **Determine Compromise State**: Search for subsequent successful login (`Accepted password`) from the same source IP:
   ```bash
   grep -E "Accepted (password|publickey) .* <SOURCE_IP>" /var/log/secure
   ```

#### Triage Runbook B: File Integrity Violation Alert
1. **Identify Modified Inode**: Note path from Wazuh alert `550`.
2. **Run Standalone Hash Verification**:
   ```bash
   python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --check --baseline evidence/sample-logs/baseline.json
   ```
3. **Identify Modifying Process & User**:
   ```bash
   sudo ausearch -f <FILE_PATH> -i
   ```

#### Triage Runbook C: Suspicious Process Alert
1. **Inspect Process Lineage**:
   ```bash
   ps -ef --forest | grep -C 5 <SUSPICIOUS_PID>
   ```
2. **Review Open Sockets & Established Connections**:
   ```bash
   sudo ss -tulpn | grep <SUSPICIOUS_PID>
   ```

---

### Phase 3: Containment
1. **Short-Term Network Isolation**:
   ```bash
   # Block offending IP immediately using iptables
   sudo iptables -I INPUT 1 -s <OFFENDING_IP> -j DROP
   ```
2. **Process Suspension**:
   ```bash
   # Freeze process for forensic dump before terminating
   kill -STOP <PID>
   # Terminate rogue execution tree
   kill -9 <PID>
   ```

---

### Phase 4: Eradication
1. Remove all malicious files, dropped scripts, and unauthorized cron entries identified during triage.
2. Check for unauthorized SSH keys in `/root/.ssh/authorized_keys` and `~/.ssh/authorized_keys`.
3. Invalidate compromised user sessions and rotate passwords.

---

### Phase 5: Recovery
1. Revert corrupted files to pristine states using Git or backup baselines.
2. Verify file integrity using `scripts/integrity_monitor.py`.
3. Restart audited daemons in a known good state.
4. Monitor telemetry for recurrence over a 24-hour observation window.

---

### Phase 6: Post-Incident Activity & Documentation
1. Create a new incident report using `incident-reports/templates/incident-report-template.md`.
2. Archive sanitized logs and alert JSON exports into `evidence/`.
3. Adjust Wazuh or Suricata detection rules to prevent future blind spots.

---

## 3. Cross-Links
- [Incident Report Template](../incident-reports/templates/incident-report-template.md)
- [Detection Rules Guide](DETECTION-RULES.md)
- [Troubleshooting Guide](TROUBLESHOOTING.md)
