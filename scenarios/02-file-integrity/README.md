# Scenario 02: File Integrity Monitoring (FIM) & Tampering Detection

## 1. Scenario Objective
Simulate file creation, unauthorized content alteration, and deletion inside a designated, monitored test sandbox (`/tmp/homelab-fim-test`) to test real-time cryptographic hash alerts and baseline verification tools.

- **MITRE ATT&CK**: [T1565.001 - Stored Data Manipulation](https://attack.mitre.org/techniques/T1565/001/)
- **Monitored Directory**: `/tmp/homelab-fim-test/`
- **Telemetry Source**: Wazuh `syscheck` engine & Linux file audit events
- **Primary Detection Method**: Wazuh Rules `550` (Modified), `554` (Added), `553` (Deleted) and `scripts/integrity_monitor.py`.

---

## 2. Tools Involved
- **Simulation**: `simulation.sh`.
- **FIM Engine**: Wazuh Syscheck daemon (`ossec-syscheckd`).
- **Python Automation**: `scripts/integrity_monitor.py`.

---

## 3. Safety Notice & Scoping
> [!NOTE]
> All file operations are confined strictly to `/tmp/homelab-fim-test/`. The script does not alter production configuration files or system executables.

---

## 4. Execution Workflow
1. Initialize a test baseline with the Python script:
   ```bash
   mkdir -p /tmp/homelab-fim-test
   echo "Initial safe configuration" > /tmp/homelab-fim-test/config.cfg
   python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --init --baseline /tmp/homelab-fim-test/baseline.json
   ```
2. Execute the simulation script to create, modify, and delete files:
   ```bash
   bash scenarios/02-file-integrity/simulation.sh --dir /tmp/homelab-fim-test
   ```
3. Run the automated integrity verification:
   ```bash
   python3 scripts/integrity_monitor.py --dir /tmp/homelab-fim-test --check --baseline /tmp/homelab-fim-test/baseline.json
   ```

---

## 5. Investigation & Remediation
- **Investigation**: Review the diff between the previous cryptographic SHA-256 hash and the new hash.
- **Remediation**:
  - Restore altered files from secure backups or version control.
  - Revoke write privileges using `chmod 644` or `chattr +i` (immutable bit) for mission-critical files.
