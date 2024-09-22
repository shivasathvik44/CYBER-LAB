# Detection Engineering: Authentication & Brute-Force Activity

This section documents detection logic and rules targeting unauthorized authentication attempts, credential stuffing, and brute-force attacks against Linux endpoints.

---

## MITRE ATT&CK Mapping

- **Tactic**: Credential Access ([TA0006](https://attack.mitre.org/tactics/TA0006/))
- **Techniques**:
  - Password Guessing ([T1110.001](https://attack.mitre.org/techniques/T1110/001/))
  - Password Spraying ([T1110.003](https://attack.mitre.org/techniques/T1110/003/))
  - Valid Accounts: Local Accounts ([T1078.003](https://attack.mitre.org/techniques/T1078/003/))

---

## Telemetry Sources

1. **Fedora / RHEL**: `/var/log/secure`
2. **Debian / Ubuntu**: `/var/log/auth.log`
3. **Event IDs & Strings**:
   - `sshd[PID]: Failed password for <user> from <ip> port <port> ssh2`
   - `sshd[PID]: Failed password for invalid user <user> from <ip> port <port> ssh2`
   - `sshd[PID]: Accepted password for <user> from <ip> port <port> ssh2`

---

## Detection Logic & Wazuh Rules

Wazuh provides default rule ID `5710` for single SSH authentication failures. We introduce custom correlated rules in `deployment/wazuh/config/local_rules.xml`:

```xml
<group name="local,syslog,sshd,">

  <!-- Rule 100001: Threshold-based SSH Brute-Force Alert -->
  <rule id="100001" level="10" frequency="6" timeframe="120">
    <if_matched_sid>5710</if_matched_sid>
    <same_source_ip />
    <description>Homelab: High frequency SSH authentication failures from single IP (Possible Brute-Force)</description>
    <mitre>
      <id>T1110.001</id>
    </mitre>
    <group>authentication_failures,</group>
  </rule>

  <!-- Rule 100002: Direct Root Login Attempt -->
  <rule id="100002" level="8">
    <if_sid>5710</if_sid>
    <match>Failed password for root</match>
    <description>Homelab: Direct SSH failed login attempt for root user</description>
    <mitre>
      <id>T1078.003</id>
    </mitre>
  </rule>

</group>
```

---

## Investigation Runbook

When Rule `100001` fires:
1. **Identify Source IP**: Extract the offending IP address from the alert payload.
2. **Determine Targeted Accounts**: Review whether legitimate system accounts (e.g., `root`, `admin`) or random usernames were targeted.
3. **Verify Success/Failure State**: Search for subsequent rule `5715` (SSH successful login) from the identical source IP within the next 30 minutes.
4. **Automated Triage**: Run the homelab log analyzer:
   ```bash
   python3 scripts/log_analyzer.py --file /var/log/secure --threshold 5
   ```

---

## False Positive Mitigation & Tuning

- **Legitimate User Password Typos**: A threshold of 6 failures within 120 seconds prevents single typo alerts.
- **Vulnerability Scanners**: Automated network scans may trigger this rule; correlate with port scan telemetry from Suricata (Rule `1000001`).
