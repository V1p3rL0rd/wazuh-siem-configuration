#!/usr/bin/env bash
# ==============================================================================
# Wazuh Agent Automated Installer & Hardener for Ubuntu Server
# ==============================================================================
set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
ENV_FILE="${DIR}/../../.env"
[ ! -f "${ENV_FILE}" ] && ENV_FILE="${DIR}/../../docker/.env"

# Auto-detect Wazuh Manager IP/FQDN from .env if present and not provided via CLI
DEFAULT_MANAGER="<WAZUH_MANAGER_IP>"
if [ -f "${ENV_FILE}" ]; then
    ENV_MANAGER=$(grep -E '^(WAZUH_SERVER_IP|WAZUH_SERVER_FQDN)=' "${ENV_FILE}" | head -n1 | cut -d'=' -f2- | tr -d '"' | tr -d "'" || true)
    [ -n "${ENV_MANAGER}" ] && DEFAULT_MANAGER="${ENV_MANAGER}"
fi

WAZUH_MANAGER="${1:-${DEFAULT_MANAGER}}"
AGENT_NAME="${2:-$(hostname)}"

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] This script must be run as root (or with sudo)." >&2
    exit 1
fi

if [ "${WAZUH_MANAGER}" = "<WAZUH_MANAGER_IP>" ]; then
    echo "[ERROR] Please specify the Wazuh Manager IP or FQDN." >&2
    echo "Usage: sudo bash install-ubuntu.sh [WAZUH_MANAGER_IP_OR_FQDN] [AGENT_NAME]" >&2
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
WAZUH_MANAGER="${WAZUH_MANAGER}" WAZUH_AGENT_NAME="${AGENT_NAME}" apt-get install -y wazuh-agent

echo "==> 3. Applying optimized ossec.conf configuration..."
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
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

echo "==> Wazuh Agent installed and registered successfully as '${AGENT_NAME}' pointing to '${WAZUH_MANAGER}'!"
systemctl status wazuh-agent --no-pager
