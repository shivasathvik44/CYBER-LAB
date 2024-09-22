# Free Online Homelab Guide: GitHub Codespaces

This guide provides a complete, beginner-friendly walkthrough to run, experiment with, and document the **Cybersecurity Homelab** entirely within your web browser for free using **GitHub Codespaces**.

---

## 1. Why GitHub Codespaces?

- **100% Free**: GitHub provides every personal account with 60 hours per month of free Codespaces compute (2-core / 4 GB RAM or 4-core / 8 GB RAM).
- **Zero Local Installation**: No need to install VirtualBox, VMware, or dual-boot Linux on your local machine.
- **Instant Reproducibility**: The included `.devcontainer` automatically configures Python 3.11, installs testing tools (`pytest`, `ruff`, `pyyaml`), sets executable permissions, and validates the environment in under 60 seconds.
- **Cross-Platform**: Operates seamlessly on Windows, macOS, Chromebooks, and Linux directly in your web browser.

---

## 2. Step-by-Step: Opening the Lab in GitHub Codespaces

Follow these exact steps:

1. **Navigate to the Repository on GitHub**:
   Go to your repository: `https://github.com/shivasathvik44/cybersecurity-homelab` (or your personal fork).

2. **Launch a Codespace**:
   - Click the green **`<> Code`** button at the top right of the file list.
   - Select the **`Codespaces`** tab.
   - Click **`Create codespace on main`**.

   ```text
   +-------------------------------------------------------------+
   |  [ <> Code  v ]                                             |
   |  +-------------------------------------------------------+  |
   |  | Local  |  Codespaces (active)                         |  |
   |  |                                                       |  |
   |  |  +-------------------------------------------------+  |  |
   |  |  |  Create codespace on main                       |  |  |
   |  |  +-------------------------------------------------+  |  |
   +--+-------------------------------------------------------+--+
   ```

3. **Wait for Container Initialization**:
   - The browser opens a full VS Code web editor.
   - Behind the scenes, Codespaces pulls the lightweight dev container image and automatically runs `.devcontainer/setup.sh`.
   - Setup installs dependencies, configures permissions, and executes the unit test suite.

4. **Open the Terminal**:
   - If the terminal is not already visible at the bottom, press **`Ctrl + \``** (or **`Cmd + \``** on macOS), or click the hamburger menu `≡` -> **`Terminal`** -> **`New Terminal`**.

---

## 3. Pre-Flight Health Check

In the Codespaces terminal, run the environment health check:

```bash
bash scripts/health_check.sh
```

**Expected Outcome**:
- `python3`, `git`, `curl`, `bash`, `jq` will report `[PASS]`.
- System memory and disk space will report `[PASS]` or `[INFO]`.
- Summary will indicate `0 Failures`, confirming the online environment is ready.

---

## 4. Experiment 1: File Integrity Monitoring (FIM)

File Integrity Monitoring is a cornerstone defensive control required by industry standards such as PCI DSS (Requirement 11.5) and NIST SP 800-53. This experiment demonstrates how cryptographic hashing identifies tampering across critical configurations.

### Option A: Automated Single-Command Demonstration
To run the full 9-step demonstration with colorized terminal output:

```bash
bash scenarios/02-file-integrity/run_demo.sh
```

Or use the shortcut:
```bash
bash scripts/run_fim_demo.sh
```

**What the demo proves**:
1. Creates an isolated sandbox (`.fim_demo_lab`) with sample config, policy, and code files.
2. Generates a pristine SHA-256 cryptographic baseline.
3. Confirms clean integrity verification (0 anomalies on unchanged files).
4. Simulates adversary modification (injects unauthorized parameter into `config.ini`).
5. Simulates adversary file injection (drops `backdoor.sh`).
6. Simulates adversary evidence deletion (removes `policy.json`).
7. Executes delta comparison, detecting all three anomaly categories simultaneously.
8. Tests safety handling on unreadable/inaccessible files without crashing.
9. Tests graceful exception handling against corrupted baseline files.
10. Exports a structured forensic JSON report to `evidence/alert-exports/fim_demo_report.json`.

---

### Option B: Hands-On Manual FIM Walkthrough

For deeper learning, run each step manually:

#### Step 1: Create a Sandbox Directory
```bash
mkdir -p my_test_lab
echo "server_port=8080" > my_test_lab/app.conf
echo "secure_mode=true" > my_test_lab/security.cfg
```

#### Step 2: Establish the Baseline
```bash
python3 scripts/integrity_monitor.py --dir my_test_lab --init --baseline my_baseline.json
```
Inspect the generated baseline snapshot:
```bash
cat my_baseline.json | jq .
```

#### Step 3: Verify Clean State
```bash
python3 scripts/integrity_monitor.py --dir my_test_lab --check --baseline my_baseline.json
```
Output: `Status: ✅ INTEGRITY VERIFIED (CLEAN)`. Exit code is `0`.

#### Step 4: Induce Tampering
```bash
# Modify existing file
echo "backdoor_access=true" >> my_test_lab/app.conf

# Add unauthorized script
echo 'echo "bad stuff"' > my_test_lab/malicious.sh

# Delete security policy
rm my_test_lab/security.cfg
```

#### Step 5: Detect the Tampering
```bash
python3 scripts/integrity_monitor.py --dir my_test_lab --check --baseline my_baseline.json
```
Output: `Status: ⚠️  TAMPERING DETECTED`. Returns exit code `2` with detailed diffs.

#### Step 6: Export JSON Evidence
```bash
python3 scripts/integrity_monitor.py \
  --dir my_test_lab \
  --check \
  --baseline my_baseline.json \
  --json \
  --output evidence/alert-exports/manual_fim_test.json
```

Clean up when done:
```bash
rm -rf my_test_lab my_baseline.json
```

---

## 5. Experiment 2: Authentication Log Triage

In an enterprise SOC, analysts frequently analyze authentication logs to identify brute-force attacks and password spraying.

Run the log analyzer against a sample log:
```bash
# Create a sample authentication log
cat << 'EOF' > /tmp/sample_auth.log
Nov 14 10:00:01 web01 sshd[1001]: Failed password for invalid user admin from 192.168.1.105 port 49152 ssh2
Nov 14 10:00:03 web01 sshd[1002]: Failed password for invalid user admin from 192.168.1.105 port 49154 ssh2
Nov 14 10:00:05 web01 sshd[1003]: Failed password for root from 192.168.1.105 port 49156 ssh2
Nov 14 10:00:07 web01 sshd[1004]: Failed password for user1 from 192.168.1.105 port 49158 ssh2
Nov 14 10:00:09 web01 sshd[1005]: Failed password for test from 192.168.1.105 port 49160 ssh2
Nov 14 10:00:11 web01 sshd[1006]: Failed password for guest from 192.168.1.105 port 49162 ssh2
Nov 14 10:00:15 web01 sshd[1007]: Accepted password for deploy from 10.0.0.15 port 51230 ssh2
EOF

# Triage using the analyzer
python3 scripts/log_analyzer.py --file /tmp/sample_auth.log --threshold 5

# Export as JSON
python3 scripts/log_analyzer.py --file /tmp/sample_auth.log --threshold 5 --json
```

Clean up:
```bash
rm -f /tmp/sample_auth.log
```

---

## 6. Running Unit Tests and Linting

Verify software reliability in Codespaces:

```bash
# Run test suite with pytest
pytest -v tests/

# Run Ruff linter
ruff check .
```

---

## 7. Documenting Your Work

After completing an experiment, open [`docs/EXPERIMENT_LOG.md`](EXPERIMENT_LOG.md), fill in your observations, copy terminal outputs into the log, and save it. This creates tangible proof of your hands-on investigative skills for internship and job interviews.

---

## 8. Codespaces Technical Boundaries & Environment Comparison

Understanding the difference between an unprivileged container environment and a full bare-metal/VM environment is critical for a defensive engineer:

| Component / Experiment | Runs in Free Codespaces? | Why / Limitation | Where to Run Full Setup |
|---|---|---|---|
| **Python Automation Tools** (`log_analyzer.py`, `integrity_monitor.py`) | **YES (100%)** | Pure Python standard library with no root or kernel dependencies. | Anywhere (Codespaces, Linux, macOS, Windows). |
| **File Integrity Monitoring (FIM)** (Scenario 02) | **YES (100%)** | Sandbox directory hashing runs entirely in user-space. | Anywhere. |
| **Authentication Log Analysis** (Scenario 01) | **YES (100%)** | Log parsing and IP correlation runs on offline/sample log files. | Anywhere. |
| **OWASP Juice Shop Target** (Scenario 04) | **YES (Lightweight)** | Can run as a single container (`docker run -p 3000:3000 bkimminich/juice-shop`). | Codespaces or local Docker. |
| **Linux `auditd` Syscall Auditing** | **NO** | Codespaces runs in an unprivileged container where `CAP_AUDIT_CONTROL` is dropped and `/dev/audit` kernel netlink sockets are inaccessible. `auditctl` fails with `Operation not permitted`. | Dedicated Linux VM (Fedora/Ubuntu VM on bare metal, AWS EC2, Proxmox). |
| **Suricata NIDS Promiscuous Sniffing** | **NO (Live capture)** | Promiscuous packet sniffing via `af-packet` requires `CAP_NET_ADMIN` and `CAP_NET_RAW` to capture foreign traffic crossing container interfaces. | Dedicated Linux VM or physical network tap. |
| **Full Wazuh Indexer Cluster** | **NO** | Wazuh Indexer (OpenSearch backend) requires `vm.max_map_count=262144` and at least 4–6 GB dedicated RAM. Codespaces free-tier instances encounter OOM kills (exit 137). | Dedicated Linux VM with >= 8 GB RAM. |

---

## 9. Managing Your Codespaces Quota

- **Auto-Stop**: Codespaces automatically shuts down after 30 minutes of inactivity.
- **Manual Stop**: When finished, click the Codespaces icon in the bottom-left corner of VS Code (or press `F1` and type `Codespaces: Stop Current Codespace`).
- **View Usage**: Track your monthly free quota at `https://github.com/settings/billing`.
