#!/usr/bin/env bash
# ==============================================================================
# GitHub Codespaces Post-Create Setup Script
# Configures dependencies, permissions, and validates the environment.
# ==============================================================================

set -euo pipefail

GREEN="\033[0;32m"
BLUE="\033[0;34m"
BOLD="\033[1m"
NC="\033[0m"

echo -e "${BOLD}${BLUE}[*] Initializing Cybersecurity Homelab Environment in GitHub Codespaces...${NC}"

# 1. Upgrade pip and install development dependencies
echo -e "${BLUE}[*] Installing Python dependencies (pytest, ruff, pyyaml)...${NC}"
python3 -m pip install --upgrade pip
if [[ -f requirements-dev.txt ]]; then
    pip install -r requirements-dev.txt
elif [[ -f requirements.txt ]]; then
    pip install -r requirements.txt
fi

# 2. Make all scripts and simulation tools executable
echo -e "${BLUE}[*] Setting execution permissions on scripts and scenarios...${NC}"
chmod +x scripts/*.py scripts/*.sh scenarios/*/*.sh 2>/dev/null || true

# 3. Create .env from .env.example if not already present
if [[ ! -f .env && -f .env.example ]]; then
    echo -e "${BLUE}[*] Initializing .env configuration from template...${NC}"
    cp .env.example .env
fi

# 4. Run automated test suite to confirm health
echo -e "${BLUE}[*] Running test suite to verify installation...${NC}"
python3 -m unittest discover -s tests -v

echo -e "\n${BOLD}${GREEN}========================================================================${NC}"
echo -e "${BOLD}${GREEN}  CYBERSECURITY HOMELAB IS READY IN GITHUB CODESPACES!                 ${NC}"
echo -e "${BOLD}${GREEN}========================================================================${NC}"
echo -e "Quick commands to start experimenting:"
echo -e "  1. Run FIM Demo      : ${BOLD}bash scenarios/02-file-integrity/run_demo.sh${NC}"
echo -e "  2. Run Log Analyzer  : ${BOLD}python3 scripts/log_analyzer.py --file /var/log/secure --threshold 5${NC}"
echo -e "  3. Run Health Check  : ${BOLD}bash scripts/health_check.sh${NC}"
echo -e "  4. Run Unit Tests    : ${BOLD}pytest -v tests/${NC}"
echo -e "========================================================================\n"
