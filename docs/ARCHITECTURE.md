# Architecture & Data Flow Specification

This document provides a comprehensive technical architecture deep dive for the **Cybersecurity Homelab**, outlining telemetry pipelines, sensor configurations, ingestion paths, and SOC correlation layers.

---

## 1. Architectural Philosophy

The homelab architecture models an enterprise Security Operations Center (SOC) detection pipeline using open-source, industry-standard tools:
- **Defense in Depth**: Visibility at both host (endpoint) and network levels.
- **Strict Isolation**: Vulnerable targets and attack traffic are confined to non-routable private subnets.
- **Multi-Layer Telemetry**: High-fidelity correlation between kernel syscalls, authentication events, and raw packet captures.
- **Repeatable Testing**: Automated attack simulations mapped to the MITRE ATT&CK framework.

---

## 2. Component Taxonomy & Telemetry Roles

```text
+-----------------------------------------------------------------------------------+
|                              CYBERSECURITY HOMELAB                                |
+-----------------------------------------------------------------------------------+
|  ATTACK TIER             |  TELEMETRY TIER             |  DETECTION & TRIAGE TIER |
|                          |                             |                          |
|  - simulation.sh (SSH)   |  - Linux auditd             |  - Wazuh Manager (Rules) |
|  - simulation.sh (FIM)   |  - /var/log/secure (sshd)   |  - Wazuh Indexer (Store) |
|  - simulation.sh (Proc)  |  - Wazuh Syscheck (FIM)     |  - Wazuh Dashboard (UI)  |
|  - Curl / Burp Suite     |  - Suricata eve.json (NIDS) |  - log_analyzer.py       |
|  - Nmap Scan Probes      |  - HTTP Access Logs         |  - integrity_monitor.py  |
+-----------------------------------------------------------------------------------+
```

---

## 3. Detailed Telemetry Pathways

### Path A: Endpoint Host Telemetry (Auditd & PAM)
1. **Event Generation**: An adversary attempts SSH logins or executes `/tmp/unauthorized_script.sh`.
2. **Kernel Interception**: The Linux kernel intercepts the system call via `kprobes` / audit subsystem.
3. **Auditd Log Writer**: `auditd` formats the syscall record with metadata (`auid`, `euid`, `exe`, `ppid`, `comm`) into `/var/log/audit/audit.log`.
4. **Wazuh Agent Collector**: The `wazuh-agent` daemon tails `/var/log/audit/audit.log` and `/var/log/secure`.
5. **Encrypted Transport**: Telemetry is compressed, encrypted (AES-256), and streamed to Wazuh Manager over TCP port `1514`.

### Path B: Network Intrusion Detection (Suricata)
1. **Packet Capture**: Packets traversing the bridge network interface (`homelab-isolated-net`) are captured via `af-packet` in promiscuous mode.
2. **Protocol Parsing**: The Suricata engine decodes Ethernet, IP, TCP/UDP, and application layer protocols (HTTP, TLS, DNS, SSH).
3. **Signature Matching**: Payloads and headers are evaluated against `rules/local.rules` and Emerging Threats (ET) rulesets.
4. **Event Serialization**: Matching events are logged in structured JSON format to `/var/log/suricata/eve.json`.
5. **SIEM Ingestion**: Wazuh Manager reads `eve.json` and parses alerts via its native Suricata decoder.

---

## 4. Detection Correlation Pipeline

```text
[ Raw Telemetry ] 
       |
       v
[ Wazuh Pre-Decoders ] ---> Extracts timestamp, hostname, daemon name
       |
       v
[ Wazuh Decoders ] --------> Extracts srcip, dstip, srcuser, action, rule IDs
       |
       v
[ Wazuh Rules Engine ] ----> Evaluates against hierarchical XML rules
       |
       +---> Level 0-3 : Informational (logged only)
       +---> Level 4-7 : Low-to-Medium alert (stored in indexer)
       +---> Level 8-10: High severity alert (triggers SOC notification)
       +---> Level 11+ : Critical threat / Active response candidate
```

---

## 5. Security Automation & Analyst Layer

To support rapid incident triage, custom Python scripts operate alongside the SIEM:
- **`log_analyzer.py`**: Executes directly on target endpoints during an incident to isolate offending IP addresses and tally failed attempts without waiting for SIEM indexing delays.
- **`integrity_monitor.py`**: Provides standalone, verifiable cryptographic baseline audits (SHA-256) for regulatory compliance and file tampering validation.

---

## 6. Cross-Links
- [Setup Guide](LAB-SETUP.md)
- [Mermaid Architecture Diagram](../architecture/diagrams/homelab-architecture.mmd)
- [Detection Workflow Diagram](../architecture/diagrams/detection-workflow.mmd)
- [Incident Response SOP](INCIDENT-RESPONSE.md)
