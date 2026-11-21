#!/usr/bin/env bash
# ==============================================================================
# Wazuh Agent Automated Installer & Hardener for Ubuntu Server
# ==============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ENV_FILE="${DIR}/../../.env"

# Agent version must be <= manager version.
# Priority: 3rd argument > WAZUH_VERSION environment variable > WAZUH_VERSION in .env (written by setup.sh)
AGENT_VERSION="${3:-${WAZUH_VERSION:-}}"
if [ -z "${AGENT_VERSION}" ] && [ -f "${ENV_FILE}" ]; then
    AGENT_VERSION=$(grep -E '^WAZUH_VERSION=' "${ENV_FILE}" | tail -n1 | cut -d'=' -f2- | tr -d '"' | tr -d "'" | tr -d ' ' || true)
fi
AGENT_VERSION="${AGENT_VERSION#v}"

# Auto-detect Wazuh Manager IP/FQDN from .env if present and not provided via CLI
DEFAULT_MANAGER="<WAZUH_MANAGER_IP>"
if [ -f "${ENV_FILE}" ]; then
    ENV_MANAGER=$(grep -E '^(WAZUH_SERVER_IP|WAZUH_SERVER_FQDN)=' "${ENV_FILE}" | head -n1 | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
    [ -n "${ENV_MANAGER}" ] && DEFAULT_MANAGER="${ENV_MANAGER}"
fi

WAZUH_MANAGER="${1:-${DEFAULT_MANAGER}}"
AGENT_NAME="${2:-$(hostname)}"

if [ "${WAZUH_MANAGER}" = "<WAZUH_MANAGER_IP>" ] && [ -t 0 ]; then
    read -r -p "IP или FQDN Wazuh Manager: " WAZUH_MANAGER
    WAZUH_MANAGER="${WAZUH_MANAGER:-<WAZUH_MANAGER_IP>}"
fi

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (or with sudo)." >&2
    exit 1
fi

if [ "${WAZUH_MANAGER}" = "<WAZUH_MANAGER_IP>" ]; then
    echo "[ERROR] Please specify the Wazuh Manager IP or FQDN." >&2
    echo "Usage: sudo bash install-ubuntu.sh <WAZUH_MANAGER_IP_OR_FQDN> [AGENT_NAME] [AGENT_VERSION]" >&2
    exit 1
fi
if ! [[ "${WAZUH_MANAGER}" =~ ^[A-Za-z0-9.-]+$ ]]; then
    echo "[ERROR] Invalid Wazuh Manager address: ${WAZUH_MANAGER}" >&2
    exit 1
fi
if ! [[ "${AGENT_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "[ERROR] Agent version is not set. It must not be newer than the manager (check: /var/ossec/bin/wazuh-control info on the manager)." >&2
    echo "Usage: sudo bash install-ubuntu.sh <WAZUH_MANAGER_IP_OR_FQDN> [AGENT_NAME] <AGENT_VERSION, e.g. 4.14.5>" >&2
    exit 1
fi

echo "==> 1. Installing GPG key and Wazuh repository..."
apt-get update -y
apt-get install -y curl apt-transport-https lsb-release gnupg auditd

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list

apt-get update -y

echo "==> 2. Installing Wazuh Agent..."
# WAZUH_AGENT_GROUP (optional environment variable) assigns the agent to a group at enrollment
ENROLL_ENV=(WAZUH_MANAGER="${WAZUH_MANAGER}" WAZUH_AGENT_NAME="${AGENT_NAME}")
[ -n "${WAZUH_AGENT_GROUP:-}" ] && ENROLL_ENV+=(WAZUH_AGENT_GROUP="${WAZUH_AGENT_GROUP}")
env "${ENROLL_ENV[@]}" apt-get install -y "wazuh-agent=${AGENT_VERSION}-1"
# Keep the agent version: an agent newer than the manager cannot connect
apt-mark hold wazuh-agent

echo "==> 3. Applying optimized ossec.conf configuration..."
if [ -f "${DIR}/ossec.conf" ]; then
    sed "s/<WAZUH_MANAGER_IP>/${WAZUH_MANAGER}/g" "${DIR}/ossec.conf" > /var/ossec/etc/ossec.conf
else
    sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER}<\/address>/g" /var/ossec/etc/ossec.conf
fi

echo "==> 4. Deploying CIS-compliant auditd rules..."
if [ -f "${DIR}/audit.rules" ]; then
    cp "${DIR}/audit.rules" /etc/audit/rules.d/99-wazuh-secops.rules
    augenrules --load || systemctl restart auditd || true
fi

echo "==> 5. Enabling and starting Wazuh Agent service..."
systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

if systemctl is-active --quiet wazuh-agent; then
    echo "==> Wazuh Agent ${AGENT_VERSION} installed as '${AGENT_NAME}' pointing to '${WAZUH_MANAGER}'."
    echo "    Connection status: grep -E '^status' /var/ossec/var/run/wazuh-agentd.state"
else
    echo "[ERROR] wazuh-agent is not running: check /var/ossec/logs/ossec.log" >&2
    systemctl status wazuh-agent --no-pager || true
    exit 1
fi
