# Scenario 03: Suspicious Process & Reverse Shell Investigation

## 1. Scenario Objective
Simulate adversary execution patterns, including executing scripts from `/tmp`, running base64-encoded command wrappers, and simulating a mock reverse-shell socket probe, to evaluate Linux `auditd` logging and Wazuh process detection rules.

- **MITRE ATT&CK**: [T1059.004 - Unix Shell](https://attack.mitre.org/techniques/T1059/004/), [T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)
- **Target Host**: Fedora Linux Endpoint
- **Telemetry Source**: `/var/log/audit/audit.log` & `syslog`
- **Primary Detection Method**: Wazuh Rules `100010` (Execution from `/tmp`) and `100012` (Network utility execution).

---

## 2. Tools Involved
- **Simulation**: `simulation.sh`.
- **System Auditing**: `auditd` with `execve` tracking rules.
- **Triage Tools**: `ausearch`, `aureport`, `ps -ef --forest`, `ss -tulpn`.

---

## 3. Safety Notice & Scoping
> [!NOTE]
> All simulations use benign commands (e.g., executing `whoami`, `id`, or loopback probes `127.0.0.1:4444`). No external Command and Control (C2) servers or malicious payloads are utilized.

---

## 4. Execution Workflow
1. Ensure audit rules are active:
   ```bash
   sudo auditctl -l | grep process_exec
   ```
2. Run the simulation script:
   ```bash
   bash scenarios/03-suspicious-process/simulation.sh
   ```
3. Query auditd for recent process executions:
   ```bash
   sudo ausearch -k process_exec -ts recent -i
   ```

---

## 5. Investigation Runbook
1. **Find Process Lineage**: Identify parent process (`ppid`) and ancestor commands using `ps -ef --forest`.
2. **Examine Command Line**: Inspect auditd `a0`, `a1`, `a2` attributes to uncover obfuscated or encoded flags.
3. **Check Network Activity**: Determine if the process initiated network connections via `lsof -i -a -p <PID>` or `ss -tulpn`.
4. **Remediation**: Terminate suspicious process trees (`kill -9 <PID>`) and mount `/tmp` with the `noexec` option in `/etc/fstab`.
