# Monitored Linux Endpoint Configuration (Fedora)

This directory documents the telemetry instrumentation and agent configuration for the monitored Linux endpoint (Fedora Linux).

---

## Role in the Homelab

The Fedora endpoint serves as the target host for internal lateral movement, authentication abuse, file tampering, and suspicious process executions.

Key telemetry sources enabled on the endpoint:
1. **Linux Audit System (`auditd`)**: Kernel-level syscall tracking for command executions (`execve`), privilege escalation (`sudo`), and sensitive file access.
2. **System Authentication Logs (`/var/log/secure` / `auth.log`)**: Records PAM authentication events, SSH login attempts, and session openings.
3. **Wazuh Agent Daemon (`wazuh-agent`)**: Collects OS logs, performs real-time file integrity monitoring (FIM), and sends telemetry to the Wazuh Manager.

---

## Deployment Status

- [x] Baseline Linux audit rules authored (`audit/audit.rules`).
- [ ] **TODO**: Install Wazuh Agent package on the target Fedora system.
- [ ] **TODO**: Link agent to Wazuh Manager IP (`172.20.0.10`) via TLS enrollment.
- [ ] **TODO**: Load `audit.rules` into `/etc/audit/rules.d/audit.rules` and restart `auditd`.

---

## Setup Instructions

### 1. Configure Auditd Telemetry
Audit rules monitor process execution and critical security directories.

```bash
# Copy audit rules to system configuration directory
sudo cp deployment/endpoint/audit/audit.rules /etc/audit/rules.d/homelab.rules

# Load new rules into the running audit daemon
sudo augenrules --load

# Verify active rules
sudo auditctl -l
```

### 2. Configure Wazuh Agent Log Targets
Ensure `/var/ossec/etc/ossec.conf` monitors both authentication and audit logs:

```xml
<ossec_config>
  <!-- Monitor Fedora secure log -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/secure</location>
  </localfile>

  <!-- Monitor Auditd logs -->
  <localfile>
    <log_format>audit</log_format>
    <location>/var/log/audit/audit.log</location>
  </localfile>

  <!-- Real-time File Integrity Monitoring for Lab Target Directory -->
  <syscheck>
    <directories realtime="yes" check_all="yes">/tmp/homelab-fim-test</directories>
    <directories check_all="yes">/etc/passwd,/etc/shadow,/etc/sudoers</directories>
  </syscheck>
</ossec_config>
```

### 3. Verify Agent Connectivity
```bash
sudo systemctl status wazuh-agent
sudo /var/ossec/bin/agent_control -l
```
