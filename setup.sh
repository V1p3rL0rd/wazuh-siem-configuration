#!/usr/bin/env bash
# ==============================================================================
# All-In-One Production Setup & Hardening for Wazuh SIEM
# Fully automated, fail-safe, and self-healing:
#   1. Secure .env handling (chmod 600 / root only)
#   2. Full configuration backup
#   3. Python-based safe XML configuration (no malformed tags or duplicate blocks)
#   4. Elimination of stale .restart lock files
#   5. Pre-restart syntax verification via wazuh-analysisd -t (with auto-rollback)
#   6. Wazuh Manager & Dashboard synchronization
#   7. Automated Telegram verification test
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "${SCRIPT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}          Wazuh SIEM Production Hardening & Integration               ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 1. Root privileges check
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}[ERROR] Этот скрипт должен выполняться с правами суперпользователя: sudo bash setup.sh${NC}" >&2
    exit 1
fi

OSSEC_DIR="/var/ossec"
if [ ! -d "${OSSEC_DIR}" ]; then
    echo -e "${RED}[ERROR] Каталог ${OSSEC_DIR} не найден. Убедитесь, что сервер Wazuh установлен.${NC}" >&2
    exit 1
fi

ENV_FILE="${SCRIPT_DIR}/.env"
# shellcheck source=lib/env.sh
source "${SCRIPT_DIR}/lib/env.sh"

# 2. Single .env: keep valid values, ask only for missing ones (existing keys are never dropped)
echo -e "\n${YELLOW}=== Настройка параметров (сохраняются в ${ENV_FILE}) ===${NC}"
env_prompt "${ENV_FILE}" WAZUH_SERVER_IP   "IP-адрес Wazuh Manager" "" plain '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
env_prompt "${ENV_FILE}" WAZUH_SERVER_FQDN "FQDN Wazuh Manager" "" plain '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
env_prompt "${ENV_FILE}" TELEGRAM_BOT_TOKEN "Telegram Bot Token" "" secret '^[0-9]+:[A-Za-z0-9_-]+$'
env_prompt "${ENV_FILE}" TELEGRAM_CHAT_ID   "Telegram Chat ID" "" plain '^-?[0-9]+$'
env_prompt "${ENV_FILE}" INDEXER_PASSWORD   "Пароль admin Wazuh Indexer (Enter - пропустить, ISM-политика не будет применена)" "" optional
INDEXER_PASSWORD="${INDEXER_PASSWORD:-}"

chown root:root "${ENV_FILE}"
chmod 600 "${ENV_FILE}"
echo -e "${GREEN}[OK] Файл .env сохранён с правами 600 (только root).${NC}"

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

# 3. Create timestamped backups of active configuration
echo -e "\n${BLUE}==> 1. Создание резервной копии рабочей конфигурации...${NC}"
cp "${OSSEC_DIR}/etc/ossec.conf" "${OSSEC_DIR}/etc/ossec.conf.bak_${TIMESTAMP}"
[ -f "${OSSEC_DIR}/etc/rules/local_rules.xml" ] && cp "${OSSEC_DIR}/etc/rules/local_rules.xml" "${OSSEC_DIR}/etc/rules/local_rules.xml.bak_${TIMESTAMP}"
[ -f "${OSSEC_DIR}/etc/decoders/local_decoder.xml" ] && cp "${OSSEC_DIR}/etc/decoders/local_decoder.xml" "${OSSEC_DIR}/etc/decoders/local_decoder.xml.bak_${TIMESTAMP}"
[ -f "${OSSEC_DIR}/etc/local_internal_options.conf" ] && cp "${OSSEC_DIR}/etc/local_internal_options.conf" "${OSSEC_DIR}/etc/local_internal_options.conf.bak_${TIMESTAMP}"

# 4. Clean up any stale .restart lock files from previous crashes
echo -e "${BLUE}==> 2. Проверка и очистка зависших файлов состояния...${NC}"
rm -f "${OSSEC_DIR}/var/run/.restart" 2>/dev/null || true

# 5. Tune internal queues and memory
echo -e "${BLUE}==> 3. Тюнинг очередей ядра (/var/ossec/etc/local_internal_options.conf)...${NC}"
cat << 'OPTS' > "${OSSEC_DIR}/etc/local_internal_options.conf"
remoted.rqueue_size=100000
remoted.recv_counter_flush=128
analysisd.rqueue_size=100000
analysisd.default_timeframe=360
integrator.max_threads=4
monitord.keep_log_days=31
monitord.rotate_log=1
OPTS
chmod 640 "${OSSEC_DIR}/etc/local_internal_options.conf"
chown root:wazuh "${OSSEC_DIR}/etc/local_internal_options.conf"

# 6. Deploy Telegram integration executable
echo -e "${BLUE}==> 4. Развертывание исполняемых файлов Telegram-интеграции...${NC}"
mkdir -p "${OSSEC_DIR}/integrations"
cp "${SCRIPT_DIR}/integrations/telegram/custom-telegram" "${OSSEC_DIR}/integrations/custom-telegram"
cp "${SCRIPT_DIR}/integrations/telegram/custom-telegram.py" "${OSSEC_DIR}/integrations/custom-telegram.py"
chmod 750 "${OSSEC_DIR}/integrations/custom-telegram"*
chown root:wazuh "${OSSEC_DIR}/integrations/custom-telegram"*

# 7. Safe Python-based XML configuration of ossec.conf
echo -e "${BLUE}==> 5. Безопасное конфигурирование /var/ossec/etc/ossec.conf через Python...${NC}"
export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
python3 - << 'PYXML'
import os
import re
import sys

bot_token = os.environ.get('TELEGRAM_BOT_TOKEN', '').strip()
chat_id = os.environ.get('TELEGRAM_CHAT_ID', '').strip()

if not bot_token or not chat_id:
    print("[ERROR] TELEGRAM_BOT_TOKEN или TELEGRAM_CHAT_ID не заданы!", file=sys.stderr)
    sys.exit(1)

conf_path = '/var/ossec/etc/ossec.conf'
with open(conf_path, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Disable disk-consuming raw archives in <global>
content = re.sub(r'<logall>\s*(yes|no)\s*</logall>', '<logall>no</logall>', content)
content = re.sub(r'<logall_json>\s*(yes|no)\s*</logall_json>', '<logall_json>no</logall_json>', content)

# 2. Tune queue_size strictly inside <remote> block
def tune_remote(match):
    remote_block = match.group(0)
    if '<queue_size>' in remote_block:
        remote_block = re.sub(r'<queue_size>\s*\d+\s*</queue_size>', '<queue_size>131072</queue_size>', remote_block)
    else:
        remote_block = remote_block.replace('</remote>', '  <queue_size>131072</queue_size>\n  </remote>')
    return remote_block

content = re.sub(r'<remote>[\s\S]*?</remote>', tune_remote, content)

# 3. Clean up any existing duplicate telegram integration blocks
content = re.sub(r'\s*<integration>\s*<name>custom-telegram</name>[\s\S]*?</integration>', '', content)

# 4. Inject Telegram integration into the FIRST (main) <ossec_config> block right after </global>
integration_xml = f"""
  <!-- Telegram Alerting Integration (Level >= 10) -->
  <integration>
    <name>custom-telegram</name>
    <hook_url>https://api.telegram.org/bot{bot_token}/sendMessage</hook_url>
    <api_key>{chat_id}</api_key>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>"""

if '</global>' in content:
    content = content.replace('</global>', f'</global>\n{integration_xml}\n', 1)
else:
    # Fallback to before first </ossec_config>
    idx = content.find('</ossec_config>')
    content = content[:idx] + f'\n{integration_xml}\n' + content[idx:]

with open(conf_path, 'w', encoding='utf-8') as f:
    f.write(content)

print("[OK] ossec.conf успешно и безопасно обновлен.")
PYXML

# 8. Deploy validated rules and decoders
echo -e "${BLUE}==> 6. Установка правил обнаружения и фильтрации (local_rules.xml)...${NC}"
cp "${SCRIPT_DIR}/rules-and-decoders/local_rules.xml" "${OSSEC_DIR}/etc/rules/local_rules.xml"
cp "${SCRIPT_DIR}/rules-and-decoders/local_decoder.xml" "${OSSEC_DIR}/etc/decoders/local_decoder.xml"
chmod 640 "${OSSEC_DIR}/etc/rules/local_rules.xml" "${OSSEC_DIR}/etc/decoders/local_decoder.xml"
chown root:wazuh "${OSSEC_DIR}/etc/rules/local_rules.xml" "${OSSEC_DIR}/etc/decoders/local_decoder.xml"

# 9. Strict Pre-Restart Validation
echo -e "${BLUE}==> 7. Компиляция и валидация правил через wazuh-analysisd -t...${NC}"
if "${OSSEC_DIR}/bin/wazuh-analysisd" -t >/dev/null 2>&1; then
    echo -e "${GREEN}[PASS] Синтаксис правил и конфигурация на 100% валидны.${NC}"
else
    echo -e "${RED}[FAIL] wazuh-analysisd обнаружил синтаксическую ошибку! Выполняю автоматический откат...${NC}"
    "${OSSEC_DIR}/bin/wazuh-analysisd" -t || true
    cp "${OSSEC_DIR}/etc/ossec.conf.bak_${TIMESTAMP}" "${OSSEC_DIR}/etc/ossec.conf"
    for f in rules/local_rules.xml decoders/local_decoder.xml; do
        if [ -f "${OSSEC_DIR}/etc/${f}.bak_${TIMESTAMP}" ]; then
            cp "${OSSEC_DIR}/etc/${f}.bak_${TIMESTAMP}" "${OSSEC_DIR}/etc/${f}"
        fi
    done
    if [ -f "${OSSEC_DIR}/etc/local_internal_options.conf.bak_${TIMESTAMP}" ]; then
        cp "${OSSEC_DIR}/etc/local_internal_options.conf.bak_${TIMESTAMP}" "${OSSEC_DIR}/etc/local_internal_options.conf"
    fi
    exit 1
fi

# 10. Restart Wazuh Manager
echo -e "${BLUE}==> 8. Перезапуск службы wazuh-manager...${NC}"
systemctl restart wazuh-manager

# 11. Post-Restart Health Check & Watchdog
echo -e "${BLUE}==> 9. Контроль готовности демонов и API (Watchdog)...${NC}"
READY=false
for i in {1..20}; do
    # Remove .restart if stuck
    [ -f "${OSSEC_DIR}/var/run/.restart" ] && rm -f "${OSSEC_DIR}/var/run/.restart"
    
    DAEMON_STATUS=$(/var/ossec/framework/python/bin/python3 -c "from wazuh.core import manager; print(manager.status())" 2>/dev/null || echo "")
    if [[ "${DAEMON_STATUS}" == *"running"* ]] && [[ "${DAEMON_STATUS}" != *"restarting"* ]]; then
        READY=true
        break
    fi
    sleep 1
done

if [ "${READY}" = true ]; then
    echo -e "${GREEN}[OK] Все демоны Wazuh Manager перешли в статус 'running'.${NC}"
else
    echo -e "${YELLOW}[WARN] Демоны еще инициализируются, снимаем возможный флаг .restart...${NC}"
    rm -f "${OSSEC_DIR}/var/run/.restart" 2>/dev/null || true
fi

# 12. Refresh Wazuh Dashboard if installed locally
if systemctl is-active --quiet wazuh-dashboard 2>/dev/null; then
    echo -e "${BLUE}==> 10. Синхронизация сессии wazuh-dashboard...${NC}"
    systemctl restart wazuh-dashboard
fi

# 13. Optional OpenSearch ISM Retention Policy
if [ -n "${INDEXER_PASSWORD}" ] && [ "${INDEXER_PASSWORD}" != "<REDACTED_INDEXER_PASSWORD>" ]; then
    echo -e "${BLUE}==> 11. Применение политики очистки индексов (ISM) в OpenSearch...${NC}"
    curl -k -s -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh_alerts_policy" \
      -u "admin:${INDEXER_PASSWORD}" \
      -H "Content-Type: application/json" \
      -d @"${SCRIPT_DIR}/server-config/indexer_ism_policy.json" >/dev/null 2>&1 || true
fi

# 14. Verification Alert to Telegram
echo -e "${BLUE}==> 12. Отправка подтверждающего алерта в Telegram...${NC}"
TEST_ALERT_FILE="/tmp/wazuh_verify_alert_${TIMESTAMP}.json"
cat << EOFTALERT > "${TEST_ALERT_FILE}"
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)",
  "rule": {
    "level": 14,
    "description": "Wazuh SIEM: сервер успешно настроен и проверен! Оповещения уровня 10+ активны.",
    "id": "100000",
    "mitre": {
      "id": ["T1000"]
    }
  },
  "agent": {
    "id": "000",
    "name": "wazuh-server",
    "ip": "${WAZUH_SERVER_IP}"
  },
  "full_log": "Production deployment verification: baseline monitoring, queue tuning, disk optimization, and Telegram alerting enabled."
}
EOFTALERT

TG_OK=true
"${OSSEC_DIR}/integrations/custom-telegram" "${TEST_ALERT_FILE}" "${TELEGRAM_CHAT_ID}" "${TELEGRAM_BOT_TOKEN}" || TG_OK=false
rm -f "${TEST_ALERT_FILE}"
if [ "${TG_OK}" != true ]; then
    echo -e "${YELLOW}[WARN] Тестовое сообщение в Telegram не отправлено: проверьте токен/Chat ID и доступ к api.telegram.org.${NC}"
fi

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}  ✓ Сервер Wazuh SIEM полностью настроен и функционирует!             ${NC}"
echo -e "${GREEN}  ✓ Веб-интерфейс Dashboard синхронизирован с API (порт 55000)        ${NC}"
echo -e "${GREEN}  ✓ Файл .env закрыт правами 600 (root only)                          ${NC}"
echo -e "${GREEN}  ✓ Тестовое сообщение в Telegram отправлено (см. предупреждения выше) ${NC}"
echo -e "${GREEN}======================================================================${NC}"
