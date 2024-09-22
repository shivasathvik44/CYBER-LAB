# Security Incident Report: [INCIDENT-ID]

---

## 1. Incident Overview & Metadata

| Field | Detail |
|---|---|
| **Incident ID** | IR-2026-XXXX |
| **Incident Title** | [Concise Summary, e.g., SSH Brute-Force from Internal Subnet] |
| **Incident Severity** | [Critical / High / Medium / Low / Informational] |
| **Lead SOC Analyst** | Shiva Sathvik |
| **Detection Source** | [Wazuh SIEM / Suricata NIDS / auditd / Python Script] |
| **Date & Time Detected** | YYYY-MM-DD HH:MM:SS UTC |
| **Status** | [Open / Contained / Eradicated / Closed] |
| **Affected Assets** | [Hostname, IP address, Container ID] |

---

## 2. Executive Summary

Provide a 2–3 paragraph high-level overview explaining:
1. What occurred and what business/operational functionality was impacted.
2. How the activity was detected and triaged.
3. The ultimate outcome, including whether data was compromised or exfiltrated.

---

## 3. Threat Classification & MITRE ATT&CK Mapping

- **NIST Incident Category**: [Unauthorized Access / Denial of Service / Malicious Code / Improper Usage / Scans/Probes]
- **MITRE ATT&CK Tactics**:
  - Tactic: [e.g., Credential Access (TA0006)]
- **MITRE ATT&CK Techniques**:
  - Technique: [e.g., T1110.001 - Password Guessing]

---

## 4. Incident Timeline (UTC)

| Timestamp | Phase | Actor / System | Activity Description |
|---|---|---|---|
| YYYY-MM-DD HH:MM:SS | Initial Event | Attacker Node | First observed probe / connection attempt |
| YYYY-MM-DD HH:MM:SS | Detection | SIEM / Suricata | Alert rule fired in dashboard |
| YYYY-MM-DD HH:MM:SS | Triage | SOC Analyst | Analyst acknowledged alert, began host audit |
| YYYY-MM-DD HH:MM:SS | Containment | Host Firewall | Block rule enacted; socket terminated |
| YYYY-MM-DD HH:MM:SS | Recovery | System Admin | Configuration reverted; baseline hash confirmed |

---

## 5. Technical Evidence & Telemetry

### 5.1 Indicators of Compromise (IoCs)
- **Source IP Address**: `X.X.X.X`
- **Destination IP / Port**: `Y.Y.Y.Y:PORT`
- **Affected File Path**: `/path/to/file`
- **File Hashes**:
  - SHA-256 (Pre-Incident): `...`
  - SHA-256 (Post-Incident): `...`

### 5.2 Log Artifact Excerpts
```text
[Paste sanitized raw log snippets from /var/log/secure, audit.log, or eve.json here]
```

### 5.3 Wazuh / Suricata Alert Details
- **Rule ID**:
- **Alert Level**:
- **Description**:

---

## 6. Containment, Eradication & Recovery

### 6.1 Containment
- Actions taken to prevent further propagation (e.g., host isolation, firewall drop rule).

### 6.2 Eradication
- Removal of adversary artifacts, malicious processes, or unauthorized keys.

### 6.3 Recovery & Validation
- Validation that the system is clean, services restored, and FIM baseline updated.

---

## 7. Lessons Learned & Action Items

### What went well:
-

### Opportunities for improvement:
-

### Preventive Action Items:
| Action Item | Owner | Target Due Date | Priority |
|---|---|---|---|
| Tune Wazuh threshold for rule ... | Shiva Sathvik | YYYY-MM-DD | High |
| Enforce SSH key-only authentication | Shiva Sathvik | YYYY-MM-DD | Critical |
