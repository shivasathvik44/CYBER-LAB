# Detection Engineering: Network Intrusion & Threat Detection

This section documents network detection signatures, port scanning heuristics, and protocol-level anomaly alerts authored for **Suricata NIDS**.

---

## MITRE ATT&CK Mapping

- **Tactic**: Reconnaissance ([TA0043](https://attack.mitre.org/tactics/TA0043/)), Discovery ([TA0007](https://attack.mitre.org/tactics/TA0007/)), Initial Access ([TA0001](https://attack.mitre.org/tactics/TA0001/))
- **Techniques**:
  - Network Service Discovery ([T1046](https://attack.mitre.org/techniques/T1046/))
  - Active Scanning: Port Scanning ([T1595.001](https://attack.mitre.org/techniques/T1595/001/))
  - Exploit Public-Facing Application ([T1190](https://attack.mitre.org/techniques/T1190/))

---

## Telemetry Sources

1. **Suricata EVE Log**: `/var/log/suricata/eve.json`
2. **Alert Fields**:
   - `timestamp`: Event creation time
   - `src_ip`, `src_port`: Attacker socket
   - `dest_ip`, `dest_port`: Target socket
   - `alert.signature`: Rule description
   - `alert.signature_id`: Suricata SID
   - `payload`: Packet hex dump / ASCII representation

---

## Suricata Rules Deployed

Defined in `deployment/suricata/rules/local.rules`:

### 1. High-Rate TCP Port Scanning (SYN Sweep)
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

### 2. Web Attack: SQL Injection Pattern
```text
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"HOMELAB WEB SQL Injection Attempt - UNION SELECT";
    flow:to_server,established;
    content:"UNION"; nocase; http_uri;
    content:"SELECT"; nocase; http_uri;
    classtype:web-application-attack;
    sid:1000002;
    rev:1;
)
```

### 3. Web Attack: Directory Traversal
```text
alert http $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"HOMELAB WEB Directory Traversal Attempt (../)";
    flow:to_server,established;
    content:"..%2f"; nocase; http_uri;
    classtype:web-application-attack;
    sid:1000003;
    rev:1;
)
```

---

## Wazuh Correlation

Wazuh automatically decodes `eve.json` alerts matching `event_type == "alert"`. When Suricata triggers SID `1000001`, Wazuh elevates the incident severity based on target asset criticality.
