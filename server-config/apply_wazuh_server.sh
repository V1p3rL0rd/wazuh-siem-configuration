#!/usr/bin/env bash
# ==============================================================================
# Wazuh Server Optimization & Hardening Script (Production-grade)
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"

# Delegate to the master setup.sh in repository root
exec "${REPO_ROOT}/setup.sh" "$@"
