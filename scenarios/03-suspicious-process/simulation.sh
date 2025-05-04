#!/usr/bin/env bash
# ==============================================================================
# Simulation Script: Suspicious Process Activity
# Purpose: Generate process execution telemetry matching common threat behaviors.
# Safety: Fully benign; no malicious binaries or remote network connections.
# ==============================================================================

set -euo pipefail

TMP_SCRIPT="/tmp/homelab_mock_task.sh"

echo "================================================================="
echo "[*] Starting Suspicious Process Execution Simulation"
echo "================================================================="

# 1. Behavior 1: Execution of script dropped in /tmp
echo "[*] Action 1: Creating and executing script from /tmp..."
cat << 'EOF' > "$TMP_SCRIPT"
#!/bin/bash
# Benign simulation of system reconnaissance
echo "Executing simulated reconnaissance..."
id
uname -a
EOF
chmod +x "$TMP_SCRIPT"
"$TMP_SCRIPT"
rm -f "$TMP_SCRIPT"
echo "[+] Action 1 completed (Executed and cleaned up from /tmp)."

# 2. Behavior 2: Base64-obfuscated command invocation
echo "[*] Action 2: Simulating base64-encoded command string..."
# Benign command: 'echo "Homelab telemetry test"'
ENCODED="ZWNobyAiSG9tZWxhYiB0ZWxlbWV0cnkgdGVzdCI="
echo "$ENCODED" | base64 -d | bash

# 3. Behavior 3: Mock socket connection probe to local loopback
echo "[*] Action 3: Simulating local port probe (Mock C2 egress attempt)..."
python3 -c "
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1.0)
    s.connect(('127.0.0.1', 4444))
    s.close()
except Exception:
    pass
" || true

echo "================================================================="
echo "[+] Suspicious Process simulation complete."
echo "[+] Check /var/log/audit/audit.log or run 'sudo ausearch -k process_exec -ts recent'."
echo "================================================================="
