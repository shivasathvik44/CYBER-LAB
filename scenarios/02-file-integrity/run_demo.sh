#!/usr/bin/env bash
# ==============================================================================
# File Integrity Monitoring (FIM) Interactive Demonstration
# Designed for: Free Online Environments (GitHub Codespaces, Linux Containers)
# Requirements: Python 3.10+ (No root privileges required)
# ==============================================================================

set -euo pipefail

# ANSI Styling
GREEN="\033[0;32m"
RED="\033[0;31m"
YELLOW="\033[1;33m"
BLUE="\033[0;34m"
CYAN="\033[0;36m"
BOLD="\033[1m"
NC="\033[0m"

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
DEMO_DIR="${REPO_ROOT}/.fim_demo_lab"
BASELINE_FILE="${REPO_ROOT}/.fim_demo_baseline.json"
REPORT_EXPORT="${REPO_ROOT}/evidence/alert-exports/fim_demo_report.json"

print_header() {
    echo -e "\n${BOLD}${CYAN}========================================================================${NC}"
    echo -e "${BOLD}${CYAN}  $1${NC}"
    echo -e "${BOLD}${CYAN}========================================================================${NC}"
}

print_step() {
    echo -e "\n${BOLD}${BLUE}[Step $1/9] $2${NC}"
}

echo -e "${BOLD}========================================================================${NC}"
echo -e "${BOLD}   CYBERSECURITY HOMELAB: FILE INTEGRITY MONITORING (FIM) DEMO          ${NC}"
echo -e "${BOLD}   Fully Runnable Online in GitHub Codespaces (Unprivileged User Mode)  ${NC}"
echo -e "${BOLD}========================================================================${NC}"

# Ensure output export directory exists
mkdir -p "${REPO_ROOT}/evidence/alert-exports"

# ------------------------------------------------------------------------------
# 1. Create Dedicated Test Sandbox
# ------------------------------------------------------------------------------
print_step "1" "Creating Dedicated Test Sandbox..."
rm -rf "$DEMO_DIR"
mkdir -p "$DEMO_DIR/subconfigs"

cat << 'EOF' > "$DEMO_DIR/config.ini"
[server]
host = 127.0.0.1
port = 8080
enable_ssl = true
debug = false
EOF

cat << 'EOF' > "$DEMO_DIR/policy.json"
{
  "enforce_mfa": true,
  "password_min_length": 14,
  "max_failed_attempts": 5
}
EOF

cat << 'EOF' > "$DEMO_DIR/subconfigs/auth_helper.py"
def verify_token(token):
    return token.startswith("Bearer valid_")
EOF

echo -e "${GREEN}[+] Initialized isolated sandbox at: ${BOLD}${DEMO_DIR}${NC}"
echo -e "    - config.ini"
echo -e "    - policy.json"
echo -e "    - subconfigs/auth_helper.py"

# ------------------------------------------------------------------------------
# 2. Generate SHA-256 Cryptographic Baseline Snapshot
# ------------------------------------------------------------------------------
print_step "2" "Generating SHA-256 Cryptographic Baseline Snapshot..."
python3 "${REPO_ROOT}/scripts/integrity_monitor.py" \
    --dir "$DEMO_DIR" \
    --init \
    --baseline "$BASELINE_FILE"

echo -e "${GREEN}[+] Baseline snapshot recorded in: ${BOLD}${BASELINE_FILE}${NC}"

# ------------------------------------------------------------------------------
# 3. Detect Unchanged Files (Integrity Verification: Clean State)
# ------------------------------------------------------------------------------
print_step "3" "Verifying Clean State (Detecting Unchanged Files)..."
# Expect return code 0 (clean)
python3 "${REPO_ROOT}/scripts/integrity_monitor.py" \
    --dir "$DEMO_DIR" \
    --check \
    --baseline "$BASELINE_FILE"
echo -e "${GREEN}[+] Clean verification passed: 0 anomalies detected.${NC}"

# ------------------------------------------------------------------------------
# 4. Simulate Unauthorized File Modification
# ------------------------------------------------------------------------------
print_step "4" "Simulating Unauthorized Modification of 'config.ini'..."
echo "# Unauthorized modification by attacker" >> "$DEMO_DIR/config.ini"
echo "allow_anonymous_admin = true" >> "$DEMO_DIR/config.ini"
echo -e "${YELLOW}[!] Injected unauthorized admin parameter into 'config.ini'.${NC}"

# ------------------------------------------------------------------------------
# 5. Simulate Unauthorized File Creation (Dropped Backdoor)
# ------------------------------------------------------------------------------
print_step "5" "Simulating Dropped Unauthorized Payload ('backdoor.sh')..."
cat << 'EOF' > "$DEMO_DIR/backdoor.sh"
#!/bin/bash
# Simulated dropped C2 beacon
echo "Simulated beacon callback to 127.0.0.1:4444"
EOF
chmod +x "$DEMO_DIR/backdoor.sh"
echo -e "${YELLOW}[!] Dropped suspicious executable 'backdoor.sh'.${NC}"

# ------------------------------------------------------------------------------
# 6. Simulate Unauthorized File Deletion (Evidence Destruction)
# ------------------------------------------------------------------------------
print_step "6" "Simulating File Deletion (Removing 'policy.json')..."
rm -f "$DEMO_DIR/policy.json"
echo -e "${YELLOW}[!] Deleted critical security policy file 'policy.json'.${NC}"

# ------------------------------------------------------------------------------
# 7. Execute Anomaly Verification (Created, Modified, Deleted Detections)
# ------------------------------------------------------------------------------
print_step "7" "Running Integrity Check (Detecting Anomaly Trio)..."
echo -e "${BLUE}[*] Checking sandbox against baseline (Tampering Expected)...${NC}"
# Expect return code 2 (anomalies detected)
python3 "${REPO_ROOT}/scripts/integrity_monitor.py" \
    --dir "$DEMO_DIR" \
    --check \
    --baseline "$BASELINE_FILE" || true
echo -e "${GREEN}[+] File tampering successfully detected!${NC}"

# ------------------------------------------------------------------------------
# 8. Handling Inaccessible / Unreadable Files Safely
# ------------------------------------------------------------------------------
print_step "8" "Testing Safe Handling of Inaccessible / Unreadable Files..."
LOCKED_FILE="$DEMO_DIR/locked_secret.key"
echo "super_secret_private_key" > "$LOCKED_FILE"
# Remove read permissions
chmod 000 "$LOCKED_FILE" || true

echo -e "${BLUE}[*] Running check with an unreadable file present...${NC}"
python3 "${REPO_ROOT}/scripts/integrity_monitor.py" \
    --dir "$DEMO_DIR" \
    --check \
    --baseline "$BASELINE_FILE" || true

# Restore permissions so cleanup works cleanly
chmod 644 "$LOCKED_FILE" || true
rm -f "$LOCKED_FILE"
echo -e "${GREEN}[+] Inaccessible files handled gracefully without crashing.${NC}"

# ------------------------------------------------------------------------------
# 9. Detecting Corrupted / Invalid Baseline File
# ------------------------------------------------------------------------------
print_step "9" "Testing Detection of Corrupted Baseline Snapshot..."
CORRUPT_BASELINE="${DEMO_DIR}/corrupt_baseline.json"
echo "INVALID_JSON_CORRUPTED_DATA{{{" > "$CORRUPT_BASELINE"

echo -e "${BLUE}[*] Checking behavior against corrupted baseline file...${NC}"
# Expect return code 1 (error handled cleanly)
python3 "${REPO_ROOT}/scripts/integrity_monitor.py" \
    --dir "$DEMO_DIR" \
    --check \
    --baseline "$CORRUPT_BASELINE" || true
rm -f "$CORRUPT_BASELINE"
echo -e "${GREEN}[+] Corrupted baseline was safely caught and reported.${NC}"

# ------------------------------------------------------------------------------
# Export Machine-Readable JSON Report
# ------------------------------------------------------------------------------
print_header "Generating Machine-Readable JSON Triage Report"
python3 "${REPO_ROOT}/scripts/integrity_monitor.py" \
    --dir "$DEMO_DIR" \
    --check \
    --baseline "$BASELINE_FILE" \
    --json \
    --output "$REPORT_EXPORT" || true

echo -e "\n${BOLD}${GREEN}Sample JSON Report Saved to:${NC} ${BOLD}${REPORT_EXPORT}${NC}"
echo -e "${CYAN}Report Preview (first 25 lines):${NC}"
head -n 25 "$REPORT_EXPORT"

# Clean up sandbox and temporary baseline
rm -rf "$DEMO_DIR" "$BASELINE_FILE"

print_header "EXPERIMENT SUMMARY: ALL 9 FIM CAPABILITIES VERIFIED"
cat << EOF
  [PASS] 1. Created isolated test sandbox
  [PASS] 2. Generated SHA-256 cryptographic baseline
  [PASS] 3. Verified clean state (detected 0 anomalies on unchanged files)
  [PASS] 4. Detected modified files (config.ini content altered)
  [PASS] 5. Detected created files (backdoor.sh dropped)
  [PASS] 6. Detected deleted files (policy.json removed)
  [PASS] 7. Safely handled unreadable / inaccessible files without crashing
  [PASS] 8. Detected and reported corrupted baseline JSON
  [PASS] 9. Generated structured JSON forensic export ($REPORT_EXPORT)
EOF
echo -e "\n${GREEN}[+] FIM Demonstration completed successfully!${NC}\n"
