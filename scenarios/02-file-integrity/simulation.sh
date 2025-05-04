#!/usr/bin/env bash
# ==============================================================================
# Simulation Script: File Integrity Monitoring (FIM) Tampering
# Purpose: Create, modify, and delete files inside an isolated sandbox directory.
# Safety: Strictly refuses to execute on root or critical system directories.
# ==============================================================================

set -euo pipefail

TARGET_DIR="/tmp/homelab-fim-test"

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --dir <PATH>    Target sandbox directory (default: /tmp/homelab-fim-test)
  --help          Display this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir) TARGET_DIR="$2"; shift 2 ;;
        --help) print_usage; exit 0 ;;
        *) echo "[!] Unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
done

# Safety Scope Enforcement: Prevent running on critical system locations
CANONICAL_TARGET=$(mkdir -p "$TARGET_DIR" && cd "$TARGET_DIR" && pwd)

if [[ "$CANONICAL_TARGET" =~ ^(/|/etc|/bin|/sbin|/usr|/boot|/root|/var|/dev|/sys|/proc)$ ]]; then
    echo "[!] CRITICAL SAFETY ERROR: Attempted to run FIM tampering simulation against system path '$CANONICAL_TARGET'." >&2
    echo "[!] Simulation aborted to protect host integrity." >&2
    exit 2
fi

echo "================================================================="
echo "[*] Starting FIM Tampering Simulation"
echo "[*] Sandbox Directory: $CANONICAL_TARGET"
echo "================================================================="

# 1. Setup pre-existing state if not present
echo "database_host=127.0.0.1" > "$CANONICAL_TARGET/app.conf"
echo '{"enforce_tls": true}' > "$CANONICAL_TARGET/security_policy.json"
echo "[+] Seed files created (app.conf, security_policy.json)"
sleep 1

# 2. Tampering Action 1: File Modification (Appends backdoor comment)
echo "[*] Action 1: Modifying existing file 'app.conf'..."
echo "# Unauthorized modification by simulated adversary" >> "$CANONICAL_TARGET/app.conf"
echo "allow_remote_root_login=true" >> "$CANONICAL_TARGET/app.conf"

# 3. Tampering Action 2: File Creation (Drops suspicious script)
echo "[*] Action 2: Dropping new untrusted script 'unauthorized_script.sh'..."
cat << 'PAYLOAD' > "$CANONICAL_TARGET/unauthorized_script.sh"
#!/bin/bash
# Simulated dropped payload
echo "Simulated payload execution"
PAYLOAD
chmod +x "$CANONICAL_TARGET/unauthorized_script.sh"

# 4. Tampering Action 3: File Deletion (Removes security policy)
echo "[*] Action 3: Deleting 'security_policy.json'..."
rm -f "$CANONICAL_TARGET/security_policy.json"

echo "================================================================="
echo "[+] FIM Simulation completed successfully."
echo "[+] Run 'python3 scripts/integrity_monitor.py --dir $CANONICAL_TARGET --check --baseline <baseline.json>' to verify detections."
echo "================================================================="
