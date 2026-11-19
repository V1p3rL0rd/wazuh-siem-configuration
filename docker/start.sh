#!/usr/bin/env bash
# ==============================================================================
# One-Click Startup & Verification Script for Wazuh SIEM
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "${SCRIPT_DIR}"

echo "============================================================"
echo " Starting Wazuh SIEM Deployment & Verification"
echo "============================================================"

# 1. Check .env file
if [ ! -f .env ]; then
    echo "[!] .env file not found. Creating from .env.example..."
    cp .env.example .env
    echo "[!] PLEASE EDIT docker/.env with your real passwords and Telegram token before proceeding!"
    echo "    Run: nano docker/.env"
    exit 1
fi

# 2. Check Host Kernel Parameter for OpenSearch
CURRENT_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "${CURRENT_MAP}" -lt 262144 ]; then
    echo "==> Setting vm.max_map_count=262144 (requires sudo)..."
    sudo sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.d/99-wazuh.conf >/dev/null
fi

# 3. Ensure permissions on scripts and integrations
echo "==> Setting execute permissions on scripts..."
chmod +x certs/generate-certs.sh
chmod +x ../integrations/telegram/custom-telegram
chmod +x ../integrations/telegram/custom-telegram.py

# 4. Generate SSL Certificates if not present
if [ ! -f certs/root-ca.pem ] || [ ! -f certs/indexer.pem ]; then
    echo "==> Generating cluster TLS/SSL certificates..."
    ./certs/generate-certs.sh
else
    echo "==> SSL certificates already exist."
fi

# 5. Start Docker Containers
echo "==> Starting Wazuh SIEM stack via Docker Compose..."
docker compose up -d

echo "==> Waiting for Wazuh Manager to initialize configuration (20s)..."
sleep 20

# 6. Inject Telegram Integration into ossec.conf if not already present
echo "==> Checking Telegram integration in Wazuh Manager..."
docker exec -i wazuh-manager bash -c '
if ! grep -q "custom-telegram" /var/ossec/etc/ossec.conf; then
    echo "==> Injecting custom-telegram integration into /var/ossec/etc/ossec.conf..."
    sed -i "/<\/ossec_config>/i \
  <integration>\
    <name>custom-telegram</name>\
    <level>10</level>\
    <alert_format>json</alert_format>\
  </integration>" /var/ossec/etc/ossec.conf
    echo "==> Restarting wazuh-manager service to apply integration..."
    /var/ossec/bin/wazuh-control restart
else
    echo "==> custom-telegram integration already present in ossec.conf."
fi
'

echo "============================================================"
echo " Wazuh SIEM successfully started!"
echo " Web UI: https://wazuh.garuda.net/ or https://10.100.68.68/"
echo " Login: admin"
echo " Status: docker compose ps"
echo "============================================================"
