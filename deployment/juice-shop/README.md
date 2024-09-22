# OWASP Juice Shop Deployment Guide

This directory documents the deployment and security isolation controls for **OWASP Juice Shop**, which serves as the intentional web application target in the homelab.

---

## Purpose in the Homelab

OWASP Juice Shop is an intentionally insecure Node.js web application encompassing the entire OWASP Top 10 vulnerabilities. In our defensive homelab, it serves as the target for:
1. Simulating web attacks (SQL Injection, Cross-Site Scripting, Path Traversal).
2. Generating web server access logs and HTTP transaction telemetry.
3. Testing Suricata IDS HTTP inspection rules and NIDS signature triggering.
4. Analyzing web attack telemetry within Wazuh.

---

## Deployment Status

- [x] Service definition added to root `docker-compose.yml`.
- [x] Port binding restricted strictly to `127.0.0.1:3000` to prevent exposure on external LAN interfaces.
- [x] Attached to isolated bridge network `homelab-isolated-net` (Static IP: `172.20.0.20`).
- [ ] **TODO**: Launch container and verify healthcheck endpoint during testing phase.

---

## Security Precautions & Network Isolation

> [!CAUTION]
> OWASP Juice Shop contains exploitable vulnerabilities by design (remote code execution, authentication bypass, data leakage).
> - Never expose port `3000` to `0.0.0.0` or public internet interfaces.
> - Ensure all simulated attacks originate strictly from within the authorized lab subnet.

---

## Starting the Service

To start the Juice Shop container individually:

```bash
# Start container in detached mode
docker compose up -d juice-shop

# Verify container status and healthcheck
docker compose ps juice-shop
```

Verify service availability via local HTTP request:
```bash
curl -I http://127.0.0.1:3000
```
Expected output:
```text
HTTP/1.1 200 OK
Access-Control-Allow-Origin: *
X-Content-Type-Options: nosniff
...
```

To stop the service:
```bash
docker compose stop juice-shop
```
