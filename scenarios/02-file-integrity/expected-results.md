# Scenario 02: Expected Results & FIM Telemetry Analysis

This document details expected outputs from Wazuh syscheck and the custom `integrity_monitor.py` script following the FIM simulation.

---

## 1. Expected Wazuh Syscheck Alerts

When `/tmp/homelab-fim-test` is configured in `ossec.conf` with `realtime="yes"`, the following alert events trigger in Wazuh:

### Modification Event (Rule `550`)
- **Severity**: Level 7
- **Alert Text**: `Integrity checksum changed for: '/tmp/homelab-fim-test/app.conf'`
- **Attributes Tracked**: Size changed, SHA-256 hash changed, modification time (`mtime`) updated.

### File Creation Event (Rule `554`)
- **Severity**: Level 5
- **Alert Text**: `File '/tmp/homelab-fim-test/unauthorized_script.sh' added to the system.`

### File Deletion Event (Rule `553`)
- **Severity**: Level 5
- **Alert Text**: `File '/tmp/homelab-fim-test/security_policy.json' was deleted.`

---

## 2. Custom Python Script (`integrity_monitor.py`) Output

Running integrity verification against the pre-attack baseline:

```text
================================================================================
File Integrity Monitor - Verification Report
================================================================================
Target Directory   : /tmp/homelab-fim-test
Baseline Reference : /tmp/homelab-fim-test/baseline.json
Timestamp          : 2026-11-14T12:15:30Z
Status             : INTEGRITY COMPROMISED
================================================================================
SUMMARY:
  - Created Files  : 1
  - Modified Files : 1
  - Deleted Files  : 1
  - Unchanged Files: 0
--------------------------------------------------------------------------------
DETAILS:
[MODIFIED] /tmp/homelab-fim-test/app.conf
    Expected SHA-256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
    Actual SHA-256  : 4a2b91c8996fb92427ae41e4649b934ca495991b7852b855e3b0c44298fc1c14

[CREATED]  /tmp/homelab-fim-test/unauthorized_script.sh
    Current SHA-256 : 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069

[DELETED]  /tmp/homelab-fim-test/security_policy.json
    Missing from filesystem (Baseline SHA-256: 9b2d...)
================================================================================
```

---

## 3. Verification Checklist
- [ ] Baseline recorded before simulation.
- [ ] Modification of `app.conf` detected.
- [ ] Dropping of `unauthorized_script.sh` detected.
- [ ] Removal of `security_policy.json` detected.
- [ ] Syscheck / Python report generates non-zero exit code on tampering.
