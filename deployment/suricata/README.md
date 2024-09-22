# Suricata Network Intrusion Detection System (NIDS) Guide

This directory documents the deployment and configuration of **Suricata**, a high-performance Network Threat Detection engine capable of real-time intrusion detection (NIDS), inline intrusion prevention (NIPS), and network security monitoring (NSM).

---

## Purpose in the Homelab

Suricata inspects network traffic crossing the lab bridge network (`homelab-isolated-net`), providing:
1. Deep packet inspection (DPI) for protocol decoding (HTTP, TLS, DNS, SSH).
2. Signature-based detection of malicious traffic patterns (Nmap port scans, SQLi payloads, brute-force anomalies).
3. Structured event logging in JSON format (`eve.json`) for ingestion into Wazuh SIEM.

---

## Deployment Status

- [x] Configuration template prepared (`suricata.yaml`).
- [x] Custom homelab detection rules authored (`rules/local.rules`).
- [x] Container service profile configured in `docker-compose.yml`.
- [ ] **TODO**: Select traffic inspection mode (Host network interface tap vs. Docker bridge promiscuous mode).
- [ ] **TODO**: Ingest `eve.json` into Wazuh manager log collector.

---

## Configuration Files

- `suricata.yaml`: Core engine configuration, interface bindings, and logging outputs.
- `rules/local.rules`: Lab-specific signatures for detecting attack simulation scenarios.

---

## Starting Suricata with Docker

To deploy the Suricata container using the IDS profile:

```bash
docker compose --profile ids up -d suricata
```

To view live alert events from the Suricata engine:
```bash
tail -f deployment/suricata/logs/eve.json | jq 'select(.event_type=="alert")'
```

---

## Integration with Wazuh

To forward Suricata alerts into Wazuh Manager, add the following log block to the Wazuh agent or manager `ossec.conf`:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/var/log/suricata/eve.json</location>
</localfile>
```
Wazuh includes pre-built decoders and rules for Suricata alerts (`event_type: alert`).
