# Homelab Troubleshooting & Operational Diagnostics

This guide provides systematic diagnostic procedures for common operational hurdles encountered across Wazuh, Suricata, Docker, and Linux telemetry subsystems in the homelab.

---

## 1. Quick Diagnostic Triage Table

| Symptom | Component | Root Cause | Primary Fix |
|---|---|---|---|
| **Agent Disconnected (Never Connected)** | Wazuh Agent | Port 1514 blocked or wrong manager IP | Verify manager IP in `/var/ossec/etc/ossec.conf` and test `nc -zv <IP> 1514` |
| **Indexer Exits Immediately (Exit 137)** | Wazuh Indexer | Linux OOM Killer invoked | Increase host RAM or set `vm.max_map_count=262144` |
| **Suricata Capturing 0 Packets** | Suricata | Bound to wrong network interface | Run `ip link` to find bridge interface name and update `suricata.yaml` |
| **Juice Shop Exits with Permission Error** | Docker | Docker daemon non-root access | Add user to `docker` group or run with `sudo` |
| **Audit Rules Not Persisting** | Auditd | Rules overwritten on reboot | Put rules in `/etc/audit/rules.d/*.rules` and run `augenrules --load` |

---

## 2. Wazuh Component Diagnostics

### Issue A: Wazuh Agent Fails to Connect to Manager
Check the local agent log for TLS or handshake errors:
```bash
sudo tail -n 50 /var/ossec/logs/ossec.log
```
Common log entries:
- `ERROR: (4101): Waiting for server...`: Manager IP is unreachable. Test with:
  ```bash
  curl -v telnet://172.20.0.10:1514
  ```
- `ERROR: (1216): Unable to connect to any server`: Firewall on the manager host is dropping incoming packets on port 1514.

### Issue B: Wazuh Indexer OOM Crash or Map Count Warning
Check kernel max map count:
```bash
sysctl vm.max_map_count
```
If the value is below `262144`, apply the fix:
```bash
sudo sysctl -w vm.max_map_count=262144
```

---

## 3. Suricata NIDS Diagnostics

### Issue A: Interface Binding Failure
If Suricata fails to start with `af-packet: failed to open socket: No such device`:
```bash
# List all active network interfaces
ip -br link

# Test packet capture on loopback:
sudo suricata -c deployment/suricata/suricata.yaml -i lo --dump-config
```

### Issue B: Checking Packet Drops
To verify Suricata is keeping up with line rate:
```bash
grep -i "drop" /var/log/suricata/suricata.log
```

---

## 4. Docker & Container Diagnostics

### Issue A: Port Conflicts (Address Already in Use)
If `docker compose up` reports `bind: address already in use for 127.0.0.1:3000`:
```bash
# Identify which process is holding port 3000
sudo ss -tulpn | grep 3000
# Terminate the rogue process or alter JUICE_SHOP_PORT in .env
```

---

## 5. Verification Commands Reference

```bash
# Check container status
docker compose ps

# Check listening ports
ss -tulpn | grep -E "1514|55000|3000|443"

# Check active auditd rules
sudo auditctl -l

# Test log analyzer on local secure log
python3 scripts/log_analyzer.py --file /var/log/secure --threshold 1
```

---

## 6. Cross-Links
- [Lab Setup Guide](LAB-SETUP.md)
- [Architecture Guide](ARCHITECTURE.md)
- [Scripts Reference](../scripts/README.md)
