# Scenario 01: SSH Brute-Force Attack & Detection

## 1. Scenario Objective
Simulate repeated, unauthorized SSH authentication failures against the Linux endpoint to generate realistic authentication telemetry, trigger SIEM correlation thresholds, and test automated SOC log analysis tools.

- **MITRE ATT&CK**: [T1110.001 - Password Guessing](https://attack.mitre.org/techniques/T1110/001/)
- **Target**: Fedora Linux Endpoint (`172.20.0.30` or `127.0.0.1:2222`)
- **Telemetry Source**: `/var/log/secure` (Fedora) or `/var/log/auth.log` (Debian)
- **Primary Detection Method**: Wazuh Rules `5710` (single failure) and `100001` (frequency threshold).

---

## 2. Tools Involved
- **Simulation**: `simulation.sh` (custom bash script utilizing `sshpass` or netcat/ssh test loops).
- **Endpoint Daemon**: OpenSSH Server (`sshd`).
- **Detection**: Wazuh Agent & Manager.
- **Analysis**: `scripts/log_analyzer.py`.

---

## 3. Safety Notice & Scoping
> [!WARNING]
> This simulation generates rapid authentication failure logs. It is restricted to authorized lab IP addresses (`127.0.0.1` or `172.20.0.0/16`). Do not target external servers.

---

## 4. Execution Workflow
1. Verify SSH service is accessible on the target:
   ```bash
   nc -zv 127.0.0.1 22
   ```
2. Execute the simulation script:
   ```bash
   bash scenarios/01-ssh-bruteforce/simulation.sh --target 127.0.0.1 --port 22 --attempts 8
   ```
3. Run the automated log analyzer script:
   ```bash
   python3 scripts/log_analyzer.py --file /var/log/secure --threshold 5
   ```

---

## 5. Investigation & Remediation
- **Investigation**: Verify if any successful authentication (`Accepted password`) occurred from the offending IP after the failures.
- **Remediation**:
  - Implement IP blocking via Fail2ban or Wazuh Active Response.
  - Disable password-based SSH authentication in `/etc/ssh/sshd_config` (`PasswordAuthentication no`).
  - Enforce public-key authentication and MFA.
