# Scenario 04: Web Application Attack Detection

## 1. Scenario Objective
Evaluate detection of web application exploitation attempts targeting the containerized OWASP Juice Shop instance using Suricata NIDS rules and web server logs.

- **MITRE ATT&CK**: [T1190 - Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/)
- **Target**: OWASP Juice Shop (`http://127.0.0.1:3000`)
- **Telemetry Source**: Suricata `eve.json` & Node.js HTTP access traces
- **Primary Detection Method**: Suricata Rules `1000002` (SQLi) and `1000003` (Path Traversal).

---

## 2. Tools Involved
- **Target**: OWASP Juice Shop (Container).
- **Testing Clients**: `curl` test cases, Burp Suite Community Edition (optional proxy).
- **Inspection Engine**: Suricata NIDS.

---

## 3. Safety Notice & Scoping
> [!CAUTION]
> Testing payloads must only be transmitted to `127.0.0.1:3000` or `172.20.0.20:3000`. Do not reuse these test cases against public websites or unapproved infrastructure.

---

## 4. Test Suite Execution
Test cases and exact curl commands are documented in detail in `test-cases.md`:

```bash
# Example SQL Injection test case
curl -s -i "http://127.0.0.1:3000/rest/products/search?q='))%20UNION%20SELECT%201,2,3,4,5,6,7,8,9--;"
```

---

## 5. Investigation & Remediation
- **Investigation**: Verify HTTP status codes in access logs and match signature alerts in `eve.json`.
- **Remediation**:
  - Implement parameterized database queries (Object-Relational Mapping / Prepared Statements).
  - Deploy a Web Application Firewall (WAF) such as ModSecurity or AWS WAF.
  - Implement strict input validation and contextual output encoding.
