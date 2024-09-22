# Detection Engineering: File Integrity Monitoring (FIM)

This section documents detection mechanisms for unauthorized file modifications, additions, and deletions across critical system directories and monitored lab testbeds.

---

## MITRE ATT&CK Mapping

- **Tactic**: Impact ([TA0040](https://attack.mitre.org/tactics/TA0040/)), Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
- **Techniques**:
  - Data Manipulation: Stored Data Manipulation ([T1565.001](https://attack.mitre.org/techniques/T1565/001/))
  - File and Directory Permissions Modification ([T1222](https://attack.mitre.org/techniques/T1222/))
  - Hijack Execution Flow ([T1574](https://attack.mitre.org/techniques/T1574/))

---

## Telemetry Sources

1. **Wazuh Syscheck Engine**: Periodic and real-time cryptographic hash verification (MD5, SHA-1, SHA-256).
2. **Auditd File Watches**: Syscall-level file modification alerts (`-p wa`).
3. **Python Custom Baseline**: Script-driven baseline tracking (`scripts/integrity_monitor.py`).

---

## Wazuh Syscheck Configuration

In endpoint `/var/ossec/etc/ossec.conf`:

```xml
<syscheck>
  <!-- Real-time monitoring of dedicated lab sandbox -->
  <directories check_all="yes" realtime="yes">/tmp/homelab-fim-test</directories>

  <!-- Critical system identity and sudoers files -->
  <directories check_all="yes" report_changes="yes">/etc/passwd,/etc/shadow,/etc/sudoers</directories>

  <!-- Exclude noisy temporary files -->
  <ignore>/tmp/homelab-fim-test/*.tmp</ignore>
</syscheck>
```

---

## Alert Rules & Severity

| Rule ID | Level | Description | Action Required |
|---------|-------|-------------|-----------------|
| `550` | 7 | Integrity checksum changed for monitored file | Immediate verification of file diff |
| `554` | 5 | File added to the system | Verify origin and binary signatures |
| `553` | 5 | File deleted from the system | Confirm intentional administrative removal |
| `100003` | 8 | Custom rule: File tampering in lab directory | Trigger automated snapshot and triage |

---

## Investigation Workflow

1. **Review Diff**: Examine the Wazuh Dashboard `syscheck` tab to inspect the exact lines added or altered.
2. **Identify Process and User**: Correlate with `auditd` logs using the file path:
   ```bash
   sudo ausearch -f /etc/shadow -i
   ```
3. **Automated Baseline Verification**:
   ```bash
   python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --check --baseline evidence/sample-logs/baseline.json
   ```
