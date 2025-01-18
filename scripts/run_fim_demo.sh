#!/usr/bin/env bash
# Shortcut to execute the online-friendly File Integrity Monitoring experiment
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec bash "${SCRIPT_DIR}/../scenarios/02-file-integrity/run_demo.sh" "$@"
