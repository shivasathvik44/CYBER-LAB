# Security Policy

## Responsible Disclosure & Lab Safety Disclaimer

This repository, **Cybersecurity Homelab – SOC Monitoring, Threat Detection & Incident Response**, is designed exclusively for educational, research, and defensive security engineering purposes within controlled, isolated lab environments.

### ⚠️ Strict Lab Isolation Warning

The attack simulation scripts, vulnerability targets (such as OWASP Juice Shop), and detection test cases contained in this repository:
1. **Must NEVER be executed against production systems, third-party infrastructure, public networks, or unauthorized targets.**
2. **Must ONLY be run inside isolated, non-routable virtual networks** (e.g., private host-only virtual machines or internal Docker bridge networks).
3. Do not bind intentionally vulnerable software (e.g., OWASP Juice Shop, open debug ports) to `0.0.0.0` on hosts with public IP addresses or shared local networks.

Any unauthorized use of security tools or simulation scripts against external systems without prior mutual written consent is illegal and violates the Computer Fraud and Abuse Act (CFAA), the UK Computer Misuse Act, and equivalent international laws.

---

## Supported Versions & Components

Because this is an active homelab portfolio project, security updates and baseline patches are applied to the following components:

| Component | Status | Notes |
|-----------|--------|-------|
| Python Automation Scripts (`scripts/`) | Supported | Actively maintained, safe, non-destructive |
| Lab Docker Configurations (`deployment/`) | Supported | Configured for isolated lab subnets only |
| Detection Rules (`detection-rules/`) | Supported | Tested against simulated lab telemetry |
| Historical Simulation Scenarios | Static Reference | Scenarios represent bounded test fixtures |

---

## Reporting a Vulnerability

If you discover a security concern regarding this repository—such as an accidentally committed secret, a dangerous simulation script default, or an insecure configuration template that exposes the host system outside the lab:

1. **Do NOT open a public GitHub issue.**
2. Send an email to the repository owner:
   - **Maintainer**: Shiva Sathvik
   - **GitHub**: [@shivasathvik44](https://github.com/shivasathvik44)
   - **Subject**: `[SECURITY VULNERABILITY] cybersecurity-homelab - <Brief Description>`
3. Please include:
   - File and line numbers affected
   - Description of the potential risk or exposure
   - Suggested remediation or patch

We take all reports seriously and aim to acknowledge receipts within 48 hours and release fixes promptly.
