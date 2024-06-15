# Contributing to Cybersecurity Homelab

Thank you for your interest in contributing to the **Cybersecurity Homelab – SOC Monitoring, Threat Detection & Incident Response** repository. This project serves as a practical, open-source security engineering environment designed to practice defensive operations, SIEM detection engineering, and automation.

---

## Guidelines for Contributions

We welcome contributions that improve the quality, accuracy, safety, and detection coverage of this lab. Areas of interest include:
- Additional Wazuh custom rules and decoders.
- Suricata IDS signatures for emerging threat vectors.
- Enhanced Python and Bash automation scripts.
- Refined documentation, network diagrams, and incident response runbooks.

---

## Code and Contribution Standards

### 1. Safety and Isolation
- **No Destructive Operations**: Scripts must never delete arbitrary system files, disable host-level security controls permanently, or target public networks.
- **Strict Scoping**: All simulation scripts must default to lab targets (`localhost`, `127.0.0.1`, or explicit internal lab subnets like `172.20.0.0/16`).
- **No Secrets**: Never commit credentials, private keys, API tokens, or active session tokens. Use `.env.example` templates with generic placeholder values.

### 2. Python Code Standards
- Adhere to **PEP 8** style guidelines.
- Python code should support Python 3.10+.
- All helper scripts must include unit tests located in `tests/` using `pytest`.
- Handle edge cases gracefully (e.g., missing files, permission errors, malformed log lines).

### 3. Shell Script Standards
- Use `bash` with strict error handling headers (`set -euo pipefail`) where applicable.
- Add clear comments explaining simulation parameters.
- Provide dry-run or confirmation prompts when simulating high-volume traffic.

### 4. Documentation Standards
- Write in clear, technical, professional English.
- Use GitHub Flavored Markdown.
- Ensure all diagrams use valid Mermaid (`.mmd`) syntax.
- Maintain working relative links across all files in `docs/`.

---

## Submitting Pull Requests

1. **Fork** the repository and create your feature branch:
   ```bash
   git checkout -b feature/new-detection-rule
   ```
2. **Implement your changes** and add appropriate tests or verification steps.
3. **Run local tests**:
   ```bash
   pytest tests/
   ```
4. **Commit** with meaningful commit messages:
   ```bash
   git commit -m "feat(detection): add Wazuh rule for sudo privilege escalation attempts"
   ```
5. **Push** to your fork and submit a Pull Request to `main`.
6. Detail the changes, test evidence, and any relevant MITRE ATT&CK technique IDs in the PR description.
