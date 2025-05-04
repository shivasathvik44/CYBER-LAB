#!/usr/bin/env bash
# ==============================================================================
# Simulation Script: Network Port Scanning & Reconnaissance
# Purpose: Generate TCP connection bursts to trigger NIDS threshold rules.
# Safety: Strictly restricted to RFC 1918 private space and localhost.
# ==============================================================================

set -euo pipefail

TARGET_HOST="127.0.0.1"
PORT_RANGE="20-100"
SCAN_TYPE="fast"
DRY_RUN=0

print_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Options:
  --target <IP>        Target IP address (default: 127.0.0.1)
  --ports <RANGE>      Port range to scan (default: 20-100)
  --scan-type <TYPE>   Scan type: 'syn', 'connect', or 'fast' (default: fast)
  --dry-run            Print commands without executing network scan
  --help               Display this help message
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target) TARGET_HOST="$2"; shift 2 ;;
        --ports) PORT_RANGE="$2"; shift 2 ;;
        --scan-type) SCAN_TYPE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        --help) print_usage; exit 0 ;;
        *) echo "[!] Unknown option: $1" >&2; print_usage; exit 1 ;;
    esac
done

# Safety Scope Enforcement: Disallow non-private destinations
if [[ "$TARGET_HOST" != "127.0.0.1" && "$TARGET_HOST" != "localhost" && ! "$TARGET_HOST" =~ ^172\.(1[6-9]|2[0-9]|3[0-1])\. && ! "$TARGET_HOST" =~ ^10\. && ! "$TARGET_HOST" =~ ^192\.168\. ]]; then
    echo "[!] SAFETY ERROR: Target '$TARGET_HOST' is not a private IP address." >&2
    echo "[!] Aborting scan to prevent unauthorized external network probing." >&2
    exit 2
fi

echo "================================================================="
echo "[*] Starting Network Scan Simulation"
echo "[*] Target Host : $TARGET_HOST"
echo "[*] Port Range  : $PORT_RANGE"
echo "[*] Scan Mode   : $SCAN_TYPE"
echo "================================================================="

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo "[INFO] Dry run enabled. Would scan $TARGET_HOST across ports $PORT_RANGE."
    exit 0
fi

# Check if Nmap is installed, otherwise use bash /dev/tcp fallback
if command -v nmap &>/dev/null; then
    echo "[*] Executing Nmap scan..."
    case "$SCAN_TYPE" in
        syn)
            # SYN scan requires root privileges
            sudo nmap -sS -p "$PORT_RANGE" -T4 -Pn "$TARGET_HOST" || nmap -sT -p "$PORT_RANGE" -T4 -Pn "$TARGET_HOST"
            ;;
        connect)
            nmap -sT -p "$PORT_RANGE" -T4 -Pn "$TARGET_HOST"
            ;;
        fast|*)
            nmap -F -T4 -Pn "$TARGET_HOST"
            ;;
    esac
else
    echo "[!] nmap not found in PATH; executing native bash TCP socket probe fallback..."
    IFS='-' read -r START_PORT END_PORT <<< "$PORT_RANGE"
    START_PORT=${START_PORT:-20}
    END_PORT=${END_PORT:-100}

    for ((port=START_PORT; port<=END_PORT; port++)); do
        (timeout 0.2 bash -c "echo > /dev/tcp/$TARGET_HOST/$port" 2>/dev/null && echo "[+] Port $port is OPEN") || true
    done
fi

echo "================================================================="
echo "[+] Network scan simulation completed."
echo "[+] Verify detection in Suricata log (/var/log/suricata/eve.json)."
echo "================================================================="
