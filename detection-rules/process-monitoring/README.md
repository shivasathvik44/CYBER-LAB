# Detection Engineering: Process Execution & Anomaly Monitoring

This section documents detection logic for identifying anomalous process launches, reverse shell invocations, and unauthorized execution from temporary directories.

---

## MITRE ATT&CK Mapping

- **Tactic**: Execution ([TA0002](https://attack.mitre.org/tactics/TA0002/)), Defense Evasion ([TA0005](https://attack.mitre.org/tactics/TA0005/))
- **Techniques**:
  - Unix Shell ([T1059.004](https://attack.mitre.org/techniques/T1059/004/))
  - Exploitation for Privilege Escalation ([T1068](https://attack.mitre.org/techniques/T1068/))
  - Ingress Tool Transfer ([T1105](https://attack.mitre.org/techniques/T1105/))

---

## Telemetry Sources

1. **Linux Auditd**: Records all `execve` and `execveat` system calls with parent PID (`ppid`), process name (`exe`), and command-line arguments (`a0`, `a1`, `a2`).
2. **Wazuh Log Ingestion**: Ingests `/var/log/audit/audit.log` via built-in Wazuh audit decoders.

---

## Detection Rules & Indicators of Compromise (IoCs)

### 1. Execution from Temporary Directory (`/tmp` or `/dev/shm`)
Adversaries frequently drop payloads into world-writable directories.

```xml
<rule id="100010" level="8">
  <if_group>audit</if_group>
  <match>/tmp/|/dev/shm/</match>
  <description>Homelab Process: Execution of binary or script from world-writable directory (/tmp or /dev/shm)</description>
  <mitre>
    <id>T1059</id>
  </mitre>
</rule>
```

### 2. Interactive Shell Spawned by Web or Daemon Process
A web application (like Node.js or Apache) should not spawn an interactive shell (`/bin/bash`, `/bin/sh`).

```xml
<rule id="100011" level="12">
  <if_group>audit</if_group>
  <regex>pname=(node|httpd|nginx|apache2) .* exe="/usr/bin/bash"</regex>
  <description>Homelab Critical: Interactive shell spawned by web server process (Probable Web Shell / RCE)</description>
  <mitre>
    <id>T1059.004</id>
    <id>T1190</id>
  </mitre>
</rule>
```

### 3. Suspicious Networking Tools Invocation
Execution of raw socket utilities (`nc`, `ncat`, `socat`) by standard users:

```xml
<rule id="100012" level="7">
  <if_group>audit</if_group>
  <match>key="net_recon"</match>
  <description>Homelab Alert: Netcat/Ncat network utility executed</description>
  <mitre>
    <id>T1049</id>
  </mitre>
</rule>
```

---

## Investigation Checklist

1. **Process Lineage**: Check parent process tree:
   ```bash
   ps -ef --forest
   ```
2. **Auditd Event Reconstruction**:
   ```bash
   sudo ausearch -k process_exec -ts recent
   ```
3. **Network Sockets**: Identify any active outbound connections tied to the suspicious PID:
   ```bash
   sudo ss -tulpn | grep <PID>
   ```
