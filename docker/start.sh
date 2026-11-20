#!/usr/bin/env bash
# ==============================================================================
# One-Click Startup & Verification Script for Wazuh SIEM (Docker)
# Reads/creates the single project-level .env (../.env), asking only for
# values that are missing, then starts the stack.
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." >/dev/null 2>&1 && pwd)"
ENV_FILE="${REPO_ROOT}/.env"
cd "${SCRIPT_DIR}"

# shellcheck source=../lib/env.sh
source "${REPO_ROOT}/lib/env.sh"

echo "============================================================"
echo " Starting Wazuh SIEM Deployment & Verification"
echo "============================================================"

# 1. Single .env (migrate the legacy docker/.env once, never overwrite)
if [ ! -f "${ENV_FILE}" ] && [ -f "${SCRIPT_DIR}/.env" ]; then
    echo "==> Migrating legacy docker/.env to ${ENV_FILE}"
    cp "${SCRIPT_DIR}/.env" "${ENV_FILE}"
fi

echo "==> Checking configuration in ${ENV_FILE} (only missing values are requested)..."
env_prompt "${ENV_FILE}" WAZUH_SERVER_IP    "IP-адрес сервера Wazuh" "" plain '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
env_prompt "${ENV_FILE}" WAZUH_SERVER_FQDN  "FQDN сервера Wazuh" "" plain '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
env_prompt "${ENV_FILE}" INDEXER_PASSWORD   "Пароль admin для Wazuh Indexer" "" secret
env_prompt "${ENV_FILE}" API_PASSWORD       "Пароль API Wazuh (wazuh-wui)" "" secret
env_prompt "${ENV_FILE}" TELEGRAM_BOT_TOKEN "Telegram Bot Token" "" secret '^[0-9]+:[A-Za-z0-9_-]+$'
env_prompt "${ENV_FILE}" TELEGRAM_CHAT_ID   "Telegram Chat ID" "" plain '^-?[0-9]+$'
env_prompt "${ENV_FILE}" INDEXER_JVM_HEAP   "Память JVM для Indexer (не более 50% RAM)" "2g" plain '^[0-9]+[mMgG]$'
env_prompt "${ENV_FILE}" WAZUH_VERSION      "Версия образов Wazuh" "4.9.2" plain '^[0-9]+\.[0-9]+\.[0-9]+$'

# 2. Check Host Kernel Parameter for OpenSearch
CURRENT_MAP=$(sysctl -n vm.max_map_count 2>/dev/null || echo 0)
if [ "${CURRENT_MAP}" -lt 262144 ]; then
    echo "==> Setting vm.max_map_count=262144 (requires sudo)..."
    sudo sysctl -w vm.max_map_count=262144
    echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf >/dev/null
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

# 5. Validate compose file and start containers
echo "==> Validating docker compose configuration..."
docker compose --env-file "${ENV_FILE}" config --quiet

echo "==> Starting Wazuh SIEM stack via Docker Compose..."
docker compose --env-file "${ENV_FILE}" up -d

echo "==> Waiting for Wazuh Manager to initialize configuration (20s)..."
sleep 20

# 6. Inject Telegram integration into ossec.conf if not already present
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
echo " Web UI: https://${WAZUH_SERVER_FQDN}/ or https://${WAZUH_SERVER_IP}/"
echo " Login: admin"
echo " Status: docker compose --env-file ../.env ps"
echo "============================================================"
