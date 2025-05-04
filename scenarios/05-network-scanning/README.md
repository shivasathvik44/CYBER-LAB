# Scenario 05: Network Scanning & Reconnaissance Detection

## 1. Scenario Objective
Simulate adversary network discovery and port enumeration against homelab hosts to trigger Suricata NIDS scan signatures and firewall connection tracking events.

- **MITRE ATT&CK**: [T1046 - Network Service Discovery](https://attack.mitre.org/techniques/T1046/), [T1595.001 - Port Scanning](https://attack.mitre.org/techniques/T1595/001/)
- **Target**: Homelab Subnet (`172.20.0.0/16`) or Local Gateway (`127.0.0.1`)
- **Telemetry Source**: Suricata `eve.json` & Linux socket logs
- **Primary Detection Method**: Suricata Rule `1000001` (`Potential Nmap Scripting Engine or SYN Sweep`).

---

## 2. Tools Involved
- **Simulation**: `simulation.sh` using `nmap` (or standard bash `/dev/tcp` socket probe fallback).
- **Network Sensor**: Suricata NIDS.
- **Log Correlation**: Wazuh Manager.

---

## 3. Safety Notice & Scoping
> [!WARNING]
> Port scanning must only be directed at authorized private lab targets. The simulation script automatically verifies and refuses to run against public or external IP addresses.

---

## 4. Execution Workflow
1. Verify target host availability:
   ```bash
   ping -c 1 127.0.0.1
   ```
2. Execute the scanning simulation:
   ```bash
   bash scenarios/05-network-scanning/simulation.sh --target 127.0.0.1 --scan-type syn
   ```
3. Inspect Suricata alert events:
   ```bash
   tail -n 20 deployment/suricata/logs/eve.json | jq 'select(.event_type=="alert")'
   ```

---

## 5. Investigation & Remediation
- **Investigation**: Check the volume of half-open TCP connections (SYN with no ACK) using `ss -s` or `netstat`.
- **Remediation**:
  - Implement rate limiting with `iptables` / `nftables` (e.g. `hashlimit` module).
  - Close unused exposed ports and restrict administrative ports (e.g., SSH, API) via VPN or bastion host.
