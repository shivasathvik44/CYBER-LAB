#!/usr/bin/env bash
# ==============================================================================
# Cybersecurity Homelab - Environment Health Check Script
# Validates system prerequisites, container engine, memory, disk, and lab services.
# ==============================================================================

set -uo pipefail

# ANSI Color Codes
GREEN="\033[0;32m"
YELLOW="\033[1;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
BOLD="\033[1m"
NC="\033[0m"

PASS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

log_pass() {
    echo -e "  [${GREEN}PASS${NC}] $1"
    ((PASS_COUNT++))
}

log_warn() {
    echo -e "  [${YELLOW}WARN${NC}] $1"
    ((WARN_COUNT++))
}

log_fail() {
    echo -e "  [${RED}FAIL${NC}] $1"
    ((FAIL_COUNT++))
}

log_info() {
    echo -e "  [${BLUE}INFO${NC}] $1"
}

echo -e "${BOLD}========================================================================${NC}"
echo -e "${BOLD}   CYBERSECURITY HOMELAB - SYSTEM ENVIRONMENT HEALTH CHECK               ${NC}"
echo -e "${BOLD}========================================================================${NC}"

# 1. Check Required System Commands
echo -e "\n${BOLD}[1/5] Checking Required Command-Line Tools...${NC}"
REQUIRED_CMDS=("python3" "git" "curl" "bash" "awk" "sed")
for cmd in "${REQUIRED_CMDS[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        VERSION_INFO=$("$cmd" --version 2>&1 | head -n 1)
        log_pass "Command '$cmd' is available ($VERSION_INFO)"
    else
        log_fail "Missing critical command: '$cmd'. Please install via package manager."
    fi
done

# Check optional simulation / diagnostic tools
OPTIONAL_CMDS=("nmap" "jq" "ssh" "pytest")
for cmd in "${OPTIONAL_CMDS[@]}"; do
    if command -v "$cmd" &>/dev/null; then
        log_pass "Optional tool '$cmd' is installed."
    else
        log_warn "Optional tool '$cmd' not found. Some simulations or tests may use fallbacks."
    fi
done

# 2. Check Container Runtime Availability
echo -e "\n${BOLD}[2/5] Checking Container Runtime Engine...${NC}"
CONTAINER_RUNTIME=""
if command -v docker &>/dev/null; then
    CONTAINER_RUNTIME="docker"
elif command -v podman &>/dev/null; then
    CONTAINER_RUNTIME="podman"
fi

if [[ -n "$CONTAINER_RUNTIME" ]]; then
    log_pass "Container CLI '$CONTAINER_RUNTIME' found."
    if "$CONTAINER_RUNTIME" info &>/dev/null; then
        log_pass "Container engine daemon is running and responsive."
    else
        log_warn "Container daemon ($CONTAINER_RUNTIME) is not running or current user lacks socket permissions."
    fi
else
    log_warn "Neither 'docker' nor 'podman' CLI found in PATH. Container services cannot be launched."
fi

# 3. Check System Memory
echo -e "\n${BOLD}[3/5] Checking Available Memory...${NC}"
if [[ -f /proc/meminfo ]]; then
    MEM_TOTAL_KB=$(awk '/MemTotal:/ {print $2}' /proc/meminfo)
    MEM_AVAIL_KB=$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)
    MEM_TOTAL_MB=$((MEM_TOTAL_KB / 1024))
    MEM_AVAIL_MB=$((MEM_AVAIL_KB / 1024))

    log_info "Total System RAM: ${MEM_TOTAL_MB} MB | Available RAM: ${MEM_AVAIL_MB} MB"

    if (( MEM_AVAIL_MB < 2048 )); then
        log_warn "Available RAM (${MEM_AVAIL_MB} MB) is below 2048 MB. Wazuh Indexer may fail or encounter OOM errors."
    else
        log_pass "Memory capacity is sufficient for baseline container workloads."
    fi
else
    log_warn "Cannot read /proc/meminfo to verify memory."
fi

# 4. Check Disk Space
echo -e "\n${BOLD}[4/5] Checking Available Disk Space...${NC}"
DISK_AVAIL_KB=$(df -k . | awk 'NR==2 {print $4}')
DISK_AVAIL_MB=$((DISK_AVAIL_KB / 1024))
DISK_PERCENT=$(df -h . | awk 'NR==2 {print $5}' | tr -d '%')

log_info "Workspace Partition: ${DISK_AVAIL_MB} MB available (${DISK_PERCENT}% utilized)"

if (( DISK_PERCENT > 90 )); then
    log_fail "Disk utilization is critical (${DISK_PERCENT}%). Free up space before capturing pcaps or running Wazuh."
elif (( DISK_PERCENT > 80 )); then
    log_warn "Disk space usage is high (${DISK_PERCENT}%)."
else
    log_pass "Sufficient disk space available."
fi

# 5. Check Local Homelab Service Ports
echo -e "\n${BOLD}[5/5] Checking Homelab Service Ports...${NC}"
PORTS=(
    "3000:OWASP Juice Shop"
    "1514:Wazuh Agent Comm"
    "55000:Wazuh API"
    "443:Wazuh Dashboard"
)

for entry in "${PORTS[@]}"; do
    IFS=":" read -r port desc <<< "$entry"
    if (timeout 0.5 bash -c "echo > /dev/tcp/127.0.0.1/$port" 2>/dev/null); then
        log_pass "Port $port ($desc) is ACTIVE and accepting connections."
    else
        log_info "Port $port ($desc) is currently inactive (service not running yet)."
    fi
done

# Summary
echo -e "\n${BOLD}========================================================================${NC}"
echo -e "${BOLD}HEALTH CHECK SUMMARY: ${GREEN}$PASS_COUNT Passed${NC}, ${YELLOW}$WARN_COUNT Warnings${NC}, ${RED}$FAIL_COUNT Failures${NC}"
echo -e "${BOLD}========================================================================${NC}"

if (( FAIL_COUNT > 0 )); then
    echo -e "${RED}[!] Critical issues detected. Please address failed items above.${NC}"
    exit 1
else
    echo -e "${GREEN}[+] System meets core requirements for homelab operations.${NC}"
    exit 0
fi
