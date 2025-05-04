#!/usr/bin/env bash
# ==============================================================================
# Simulation Script: SSH Brute-Force Activity
# Purpose: Generate controlled, bounded authentication failures for lab testing.
# Safety: Strictly restricted to RFC 1918 and loopback addresses.
# ==============================================================================

set -euo pipefail

TARGET_HOST="127.0.0.1"
TARGET_PORT="22"
ATTEMPTS=6
TEST_USER="lab_test_user"
DRY_RUN=0

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --target <IP/HOST>    Target host (default: 127.0.0.1)
  --port <PORT>         Target SSH port (default: 22)
  --attempts <COUNT>    Number of failed attempts to simulate (default: 6)
  --user <USERNAME>     Username to test with (default: lab_test_user)
  --dry-run             Print commands without sending network traffic
  --help                Display this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_HOST="$2"; shift 2 ;;
        --port) TARGET_PORT="$2"; shift 2 ;;
        --attempts) ATTEMPTS="$2"; shift 2 ;;
        --user) TEST_USER="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help) print_usage; exit 0 ;;
        *) echo "[!] Unknown argument: $1" >&2; print_usage; exit 1 ;;
    esac
done

# Safety Scope Enforcement: Disallow public internet targets
if [[ "$TARGET_HOST" != "127.0.0.1" && "$TARGET_HOST" != "localhost" && ! "$TARGET_HOST" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. && ! "$TARGET_HOST" =~ ^10\. && ! "$TARGET_HOST" =~ ^192\.168\. ]]; then
    echo "[!] SAFETY ERROR: Target '$TARGET_HOST' is outside private RFC 1918 / loopback space." >&2
    echo "[!] Simulation aborted to prevent accidental external network scanning." >&2
    exit 2
fi

echo "================================================================="
echo "[*] Starting SSH Brute-Force Simulation"
echo "[*] Target Host : $TARGET_HOST"
echo "[*] Target Port : $TARGET_PORT"
echo "[*] Target User : $TEST_USER"
echo "[*] Attempts    : $ATTEMPTS"
echo "================================================================="

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[INFO] Dry run enabled. Would execute $ATTEMPTS failed attempts against $TARGET_HOST:$TARGET_PORT."
    exit 0
fi

# Execute simulated attempts
for ((i=1; i<=ATTEMPTS; i++)); do
    DUMMY_PASS="SimulatedWrongPass_${RANDOM}"
    echo "[*] Attempt $i of $ATTEMPTS: Attempting login for $TEST_USER..."

    # Use SSH with batch mode and mock password prompt failure
    # StrictHostKeyChecking=no, UserKnownHostsFile=/dev/null to avoid host key prompt
    ssh -o BatchMode=yes \
        -o StrictHostKeyChecking=no \
        -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=2 \
        -p "$TARGET_PORT" \
        "$TEST_USER@$TARGET_HOST" 2>/dev/null || true

    sleep 1
done

echo "[+] Simulation completed. Check /var/log/secure or run scripts/log_analyzer.py."
