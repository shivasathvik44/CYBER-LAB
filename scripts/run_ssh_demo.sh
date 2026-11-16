#!/usr/bin/env bash
# Wrapper to launch the Phase 2 SSH Brute-Force Log Analysis demonstration
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "${REPO_ROOT}/scenarios/01-ssh-bruteforce/run_demo.sh" "$@"
