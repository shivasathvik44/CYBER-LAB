# Network Topology & Addressing Plan

This document details the network architecture, subnet allocations, firewall isolation policies, and port assignments for the **Cybersecurity Homelab**.

---

## 1. Network Philosophy & Isolation Boundaries

To maintain safety and protect local home/enterprise networks:
1. **Isolated Bridge Subnet**: All lab containers operate on a private user-defined Docker bridge network named `homelab-isolated-net` (`172.20.0.0/16`).
2. **Localhost Binding**: Insecure web services (e.g. OWASP Juice Shop) bind strictly to `127.0.0.1` on the host, preventing remote exposure to external LAN devices.
3. **No Direct WAN Routing**: Simulation scripts are hardcoded with safety checks that block execution against non-RFC 1918 public IP addresses.

---

## 2. IP Addressing Matrix

| Node / Service | Host / Interface | IP Address | MAC / Port Binding | Role |
|---|---|---|---|---|
| **Bridge Gateway** | `br-homelab` | `172.20.0.1` | Default Gateway | Docker bridge gateway |
| **Wazuh Manager** | `homelab-wazuh-manager` | `172.20.0.10` | 1514 (Agent), 55000 (API) | Central SIEM Analysis |
| **OWASP Juice Shop** | `homelab-juice-shop` | `172.20.0.20` | `127.0.0.1:3000` | Vulnerable Target |
| **Fedora Endpoint** | Host / VM | `172.20.0.30` | 22 (SSH), auditd | Monitored Linux Endpoint |
| **Simulation Node** | Container / Kali | `172.20.0.99` | Ephemeral sockets | Attack Simulation Source |

---

## 3. Port Matrix & Traffic Rules

| Port | Protocol | Source | Destination | Purpose |
|---|---|---|---|---|
| **22** | TCP | Attacker (`172.20.0.99`) | Endpoint (`172.20.0.30`) | SSH simulation (Scenario 01) |
| **3000** | TCP | Attacker / Host | Juice Shop (`172.20.0.20`) | Web attack testing (Scenario 04) |
| **1514** | TCP | Endpoint Agent | Wazuh Manager (`172.20.0.10`) | Agent event forwarding |
| **1515** | TCP | Endpoint Agent | Wazuh Manager (`172.20.0.10`) | Agent registration (TLS) |
| **55000** | TCP | SOC Analyst Host | Wazuh Manager (`172.20.0.10`) | Wazuh REST API |
| **443** | TCP | SOC Analyst Browser | Wazuh Dashboard (`172.20.0.12`) | Web UI visualization |

---

## 4. Host Firewall & Traffic Isolation Rules

To enforce strict containment on the host, configure `iptables` or `firewalld`:

```bash
# Example iptables isolation rule: Drop outbound packets from lab subnet to WAN
sudo iptables -I FORWARD 1 -s 172.20.0.0/16 ! -d 172.20.0.0/16 -j DROP

# Ensure Juice Shop port is only reachable from loopback
sudo iptables -I INPUT 1 -p tcp --dport 3000 ! -s 127.0.0.1 -j DROP
```

---

## 5. Packet Capture & Tap Interface

Suricata is attached to the virtual ethernet bridge interface (`br-homelab` or host loopback `lo` in container testing) using AF_PACKET:

```bash
# Identify the Docker bridge network interface name
ip -br link | grep "br-"
```

Configure Suricata to sniff this interface in `suricata.yaml` under the `af-packet` section to observe all intra-lab traffic.

---

## 6. Cross-Links
- [Network Topology Diagram](../architecture/diagrams/network-topology.mmd)
- [Lab Setup Guide](LAB-SETUP.md)
- [Troubleshooting](TROUBLESHOOTING.md)
