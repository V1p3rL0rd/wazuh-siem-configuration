#!/usr/bin/env bash
# ==============================================================================
# quick_sec_scan.sh - Rapid Host & Repository Security Hygiene Scanner
# ==============================================================================
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

ERRORS=0
WARNINGS=0

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; WARNINGS=$((WARNINGS + 1)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ERRORS=$((ERRORS + 1)); }

echo "============================================================"
echo " Security Posture & Compliance Audit Scanner"
echo " Date: $(date -u '+%Y-%m-%d %H:%M:%SZ')"
echo "============================================================"

# 1. Plaintext Secrets Check
log_info "1. Scanning workspace for committed credentials/keys..."
SUSPICIOUS_PATTERNS=(
    "PRIVATE KEY"
    "password\s*[:=]\s*['\"][^'\"]+['\"]"
    "api[_-]?key\s*[:=]\s*['\"][^'\"]+['\"]"
    "secret[_-]?token"
)

FOUND_SECRET=0
for pat in "${SUSPICIOUS_PATTERNS[@]}"; do
    if grep -rEIin --exclude-dir=.git --exclude-dir=.agents --exclude-dir=docs --exclude="*.sh" "${pat}" . 2>/dev/null; then
        FOUND_SECRET=1
    fi
done

if [ "${FOUND_SECRET}" -eq 1 ]; then
    log_fail "Potential secrets or credentials discovered in workspace files!"
else
    log_pass "No plaintext secret patterns found in workspace."
fi

# 2. Insecure File Permissions
log_info "2. Checking for world-writable files in repository..."
WORLD_WRITABLE=$(find . -not -path "*/.git/*" -perm -0002 -type f 2>/dev/null || true)
if [ -n "${WORLD_WRITABLE}" ]; then
    log_warn "World-writable files detected:"
    echo "${WORLD_WRITABLE}"
else
    log_pass "File permissions are secure."
fi

# 3. Docker / K8s Privileged Flags Check
log_info "3. Inspecting containers for privileged flags..."
PRIV_CONTAINERS=$(grep -rn "privileged:\s*true" . --include="*.yml" --include="*.yaml" --exclude-dir=.git 2>/dev/null || true)
if [ -n "${PRIV_CONTAINERS}" ]; then
    log_warn "Containers with 'privileged: true' found:"
    echo "${PRIV_CONTAINERS}"
else
    log_pass "No unconstrained privileged containers detected."
fi

# Summary
echo "============================================================"
echo " Security Scan Summary: ${ERRORS} Errors, ${WARNINGS} Warnings"
echo "============================================================"

if [ "${ERRORS}" -gt 0 ]; then
    exit 1
else
    exit 0
fi
