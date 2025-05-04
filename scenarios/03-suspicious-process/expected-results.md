# Scenario 03: Expected Results & Process Telemetry Analysis

This document describes expected `auditd` log entries and Wazuh SIEM alerts generated during the suspicious process execution simulation.

---

## 1. Expected Auditd Telemetry

When `simulation.sh` runs, `auditd` with key `process_exec` captures the execution:

```text
type=SYSCALL msg=audit(1731602400.123:4512): arch=c000003e syscall=59 success=yes exit=0 a0=55d21a a1=55d28b a2=55d310 a3=7ffef items=2 ppid=12040 pid=14502 auid=1000 uid=1000 gid=1000 euid=1000 comm="homelab_mock_ta" exe="/tmp/homelab_mock_task.sh" key="process_exec"
type=EXECVE msg=audit(1731602400.123:4512): argc=1 a0="/tmp/homelab_mock_task.sh"
type=CWD msg=audit(1731602400.123:4512): cwd="/home/capslock/cybersecurity-homelab"
type=PATH msg=audit(1731602400.123:4512): item=0 name="/tmp/homelab_mock_task.sh" inode=983141 dev=00:2b mode=0100755 ouid=1000 ogid=1000
```

---

## 2. Expected Wazuh SIEM Alerts

### Execution from World-Writable Path (Rule `100010`)
- **Rule ID**: `100010`
- **Level**: 8
- **Description**: `Homelab Process: Execution of binary or script from world-writable directory (/tmp or /dev/shm)`
- **MITRE ATT&CK**: T1059 (Command and Scripting Interpreter)

---

## 3. Investigation Commands & Output
Running `ausearch` filters the relevant incident:

```bash
sudo ausearch -k process_exec -ts recent -i
```

Output highlights the binary path, execution time, and process owner:
```text
----
type=PROCTITLE msg=audit(11/14/2026 12:30:15.123:4512) : proctitle="/tmp/homelab_mock_task.sh"
type=PATH msg=audit(11/14/2026 12:30:15.123:4512) : item=0 name="/tmp/homelab_mock_task.sh" nametype=NORMAL
type=CWD msg=audit(11/14/2026 12:30:15.123:4512) : cwd="/home/capslock"
type=EXECVE msg=audit(11/14/2026 12:30:15.123:4512) : argc=1 a0="/tmp/homelab_mock_task.sh"
type=SYSCALL msg=audit(11/14/2026 12:30:15.123:4512) : arch=x86_64 syscall=execve success=yes exit=0 ppid=12040 pid=14502 auid=capslock uid=capslock exe="/tmp/homelab_mock_task.sh" key="process_exec"
```
