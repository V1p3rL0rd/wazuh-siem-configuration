#!/usr/bin/env bash
# Forwarding wrapper to root setup.sh
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
exec "${SCRIPT_DIR}/../setup.sh" "$@"
