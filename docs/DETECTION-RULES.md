# Detection Engineering & Rule Authoring Guide

This document outlines the detection engineering philosophy, rule authoring standards, syntax conventions, and tuning processes applied across Wazuh SIEM and Suricata NIDS in the homelab.

---

## 1. Detection Engineering Methodology

The homelab adopts the **Detection Development Lifecycle (DDLC)**:

```text
[ Threat Modeling & MITRE Mapping ]
                |
                v
[ Telemetry Source Identification ]
                |
                v
[ Signature / Logic Authoring ]
                |
                v
[ Simulation Testing & Validation ]
                |
                v
[ Tuning & False Positive Mitigation ]
                |
                v
[ Production Deployment & SOP Creation ]
```

---

## 2. Wazuh Rules Engine Specification

Wazuh processes incoming log strings in a three-stage pipeline:
1. **Pre-Decoding**: Extracts timestamp, hostname, and program name.
2. **Decoding**: Regex-based extraction of dynamic fields (e.g. `srcip`, `user`, `dstport`).
3. **Rule Evaluation**: Matches rules hierarchically based on rule groups, previous rule IDs (`if_sid`), frequency thresholds, and MITRE ATT&CK tags.

### Custom Rule Syntax Example (Frequency-Based Brute Force)
Located in `deployment/wazuh/config/local_rules.xml`:

```xml
<rule id="100001" level="10" frequency="6" timeframe="120">
  <if_matched_sid>5710</if_matched_sid>
  <same_source_ip />
  <description>Homelab: High frequency SSH authentication failures from single IP (Possible Brute-Force)</description>
  <mitre>
    <id>T1110.001</id>
  </mitre>
  <group>authentication_failures,</group>
</rule>
```

**Key Parameters**:
- `id`: Custom rule ID range (recommended: `100000` to `120000`).
- `level`: Alert severity from 0 (ignore) to 16 (emergency).
- `frequency`: Minimum matches required to trigger alert.
- `timeframe`: Time window in seconds for frequency calculation.
- `same_source_ip`: Requires subsequent events to share identical source IPs.

---

## 3. Suricata NIDS Rule Specification

Suricata inspects live network traffic using Snort-compatible signature syntax:

```text
action proto src_ip src_port -> dst_ip dst_port (rule_options;)
```

### Signature Breakdown: Port Scan Detection
Located in `deployment/suricata/rules/local.rules`:

```text
alert tcp $EXTERNAL_NET any -> $HOME_NET any (
    msg:"HOMELAB SCAN Potential Nmap Scripting Engine or SYN Sweep";
    flags:S,12;
    threshold:type both, track by_src, count 20, seconds 5;
    classtype:attempted-recon;
    sid:1000001;
    rev:1;
)
```

**Key Elements**:
- `flags:S,12`: Matches TCP SYN packets without ACK or RST.
- `threshold:type both, track by_src, count 20, seconds 5`: Limits alert generation to one alert per 5 seconds when >= 20 packets match from a single source IP.
- `sid`: Unique Signature ID (Local range: `1000000` to `1999999`).

---

## 4. False Positive Reduction & Tuning Strategies

1. **Whitelisting Trusted Infrastructure**: Exclude healthcheck probes, CI/CD runners, or internal monitoring scripts from high-severity rules.
2. **Frequency Window Tuning**: If automated vulnerability scans generate noise, increase the alert threshold or correlate with host audit logs before paging analysts.
3. **Contextual Enrichment**: Avoid alerting on isolated failed logins; require follow-up failed logins across multiple user accounts or successful logins immediately following failures.

---

## 5. Cross-Links
- [Custom Wazuh Rules File](../deployment/wazuh/config/local_rules.xml)
- [Suricata Signatures File](../deployment/suricata/rules/local.rules)
- [Linux Audit Rules](../deployment/endpoint/audit/audit.rules)
- [Incident Response SOP](INCIDENT-RESPONSE.md)
