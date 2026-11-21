#!/usr/bin/env bash
# ==============================================================================
# Wazuh SIEM: manager hardening, detection rules and Telegram alerting
#   1. Settings in a single .env (chmod 600, root only)
#   2. Backup of every file that is changed (restored automatically on failure)
#   3. Safe edits of ossec.conf / local_internal_options.conf (lib/ossec_conf.py)
#   4. Detection rules and decoders (refuses to drop rules that are not in the repository)
#   5. Validation BEFORE restart: wazuh-analysisd -t, wazuh-remoted -t, wazuh-logtest cases
#   6. Restart with health check and automatic rollback
#   7. Optional OpenSearch ISM retention policy
#   8. Telegram test message
#
# Usage: sudo bash setup.sh [--force-rules]
# ==============================================================================
set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "${SCRIPT_DIR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

info() { echo -e "${BLUE}$*${NC}"; }
ok()   { echo -e "${GREEN}[OK] $*${NC}"; }
warn() { echo -e "${YELLOW}[WARN] $*${NC}" >&2; }
die()  { echo -e "${RED}[ERROR] $*${NC}" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: sudo bash setup.sh [--force-rules]

  --force-rules   replace /var/ossec/etc/rules/local_rules.xml and local_decoder.xml even if they
                  contain rules/decoders that are not in this repository (a backup is kept)
  -h, --help      this help
EOF
}

FORCE_RULES=0
for arg in "$@"; do
    case "${arg}" in
        --force-rules) FORCE_RULES=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage; die "Неизвестный параметр: ${arg}" ;;
    esac
done

BACKUP_DIR=""
on_error() {
    local rc=$? line=$1
    echo -e "${RED}[ERROR] Непредвиденная ошибка (код ${rc}) в строке ${line}.${NC}" >&2
    [ -n "${BACKUP_DIR}" ] && echo -e "${RED}        Резервная копия: ${BACKUP_DIR} (восстановление: см. MANIFEST).${NC}" >&2
    exit "${rc}"
}
trap 'on_error $LINENO' ERR

echo -e "${BLUE}======================================================================${NC}"
echo -e "${BOLD}${BLUE}          Wazuh SIEM Production Hardening & Integration               ${NC}"
echo -e "${BLUE}======================================================================${NC}"

# 1. Root privileges check
[ "${EUID}" -eq 0 ] || die "Этот скрипт должен выполняться с правами суперпользователя: sudo bash setup.sh"

OSSEC_DIR="/var/ossec"
[ -d "${OSSEC_DIR}" ] || die "Каталог ${OSSEC_DIR} не найден. Убедитесь, что сервер Wazuh установлен."
[ -x "${OSSEC_DIR}/bin/wazuh-analysisd" ] || die "${OSSEC_DIR}/bin/wazuh-analysisd не найден: это не Wazuh manager."

if command -v python3 >/dev/null 2>&1; then
    PYTHON="$(command -v python3)"
elif [ -x "${OSSEC_DIR}/framework/python/bin/python3" ]; then
    PYTHON="${OSSEC_DIR}/framework/python/bin/python3"
else
    die "python3 не найден."
fi

ENV_FILE="${SCRIPT_DIR}/.env"
# shellcheck source=lib/env.sh
source "${SCRIPT_DIR}/lib/env.sh"

# 2. Single .env: keep valid values, ask only for missing ones (existing keys are never dropped)
echo -e "\n${YELLOW}=== Настройка параметров (сохраняются в ${ENV_FILE}) ===${NC}"

DEFAULT_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -n1 || true)"
[ -n "${DEFAULT_IP}" ] || DEFAULT_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
DEFAULT_FQDN="$(hostname -f 2>/dev/null || hostname 2>/dev/null || true)"

# Manager version: agents must not be newer than the manager ("v4.14.5" -> "4.14.5")
DETECTED_VER="$("${OSSEC_DIR}/bin/wazuh-control" info 2>/dev/null | sed -n 's/^WAZUH_VERSION="v\{0,1\}\([0-9][0-9.]*\)".*/\1/p' | head -n1 || true)"
[ -n "${DETECTED_VER}" ] || DETECTED_VER="$("${OSSEC_DIR}/bin/wazuh-analysisd" -V 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -n1 || true)"

env_prompt "${ENV_FILE}" WAZUH_SERVER_IP    "IP-адрес Wazuh Manager" "${DEFAULT_IP}" plain '^([0-9]{1,3}\.){3}[0-9]{1,3}$'
env_prompt "${ENV_FILE}" WAZUH_SERVER_FQDN  "FQDN Wazuh Manager" "${DEFAULT_FQDN}" plain '^[A-Za-z0-9]([A-Za-z0-9.-]*[A-Za-z0-9])?$'
env_prompt "${ENV_FILE}" WAZUH_VERSION      "Версия Wazuh для агентов (не новее менеджера)" "${DETECTED_VER}" plain '^[0-9]+\.[0-9]+\.[0-9]+$'
env_prompt "${ENV_FILE}" TELEGRAM_BOT_TOKEN "Telegram Bot Token" "" secret '^[0-9]+:[A-Za-z0-9_-]+$'
env_prompt "${ENV_FILE}" TELEGRAM_CHAT_ID   "Telegram Chat ID" "" plain '^-?[0-9]+$'
env_prompt "${ENV_FILE}" INDEXER_PASSWORD   "Пароль admin Wazuh Indexer (Enter - пропустить, ISM-политика не будет применена)" "" optional
INDEXER_PASSWORD="${INDEXER_PASSWORD:-}"

chown root:root "${ENV_FILE}"
chmod 600 "${ENV_FILE}"
ok "Файл .env сохранён с правами 600 (только root)."

TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
SRV_RULES="${OSSEC_DIR}/etc/rules/local_rules.xml"
SRV_DECODER="${OSSEC_DIR}/etc/decoders/local_decoder.xml"
REPO_RULES="${SCRIPT_DIR}/rules-and-decoders/local_rules.xml"
REPO_DECODER="${SCRIPT_DIR}/rules-and-decoders/local_decoder.xml"

# 3. Pre-flight: never silently drop rules/decoders that are not part of this repository
info "==> 0. Проверка существующих правил и декодеров..."
rule_ids()      { grep -oE '<rule[[:space:]]+id="[0-9]+"' "$1" 2>/dev/null | grep -oE '[0-9]+' | sort -u || true; }
decoder_names() { grep -oE '<decoder[[:space:]]+name="[^"]+"' "$1" 2>/dev/null | sed 's/.*name="//; s/"$//' | sort -u || true; }

EXTRA_RULES="$(comm -13 <(rule_ids "${REPO_RULES}") <(rule_ids "${SRV_RULES}") | tr '\n' ' ')"
# Decoders shipped by earlier versions of this repository are replaced without asking
LEGACY_DECODERS="custom-auditd-tag"
EXTRA_DECODERS="$(comm -13 <({ decoder_names "${REPO_DECODER}"; tr ' ' '\n' <<<"${LEGACY_DECODERS}"; } | sort -u) \
    <(decoder_names "${SRV_DECODER}") | tr '\n' ' ')"
if [ -n "${EXTRA_RULES// /}${EXTRA_DECODERS// /}" ]; then
    if [ "${FORCE_RULES}" -eq 1 ]; then
        warn "--force-rules: будут удалены правила [${EXTRA_RULES}] и декодеры [${EXTRA_DECODERS}] (копия сохранится в backup)."
    else
        die "local_rules.xml / local_decoder.xml на сервере содержат то, чего нет в репозитории:
        правила: ${EXTRA_RULES:-—}
        декодеры: ${EXTRA_DECODERS:-—}
        setup.sh заменяет эти файлы. Перенесите свои правила и декодеры в отдельные файлы, например
        ${OSSEC_DIR}/etc/rules/custom_rules.xml и ${OSSEC_DIR}/etc/decoders/custom_decoders.xml
        (Wazuh загружает все файлы этих каталогов), или запустите: sudo bash setup.sh --force-rules"
    fi
fi
CONFLICTS=""
shopt -s nullglob
for f in "${OSSEC_DIR}"/etc/rules/*.xml; do
    [ "${f}" = "${SRV_RULES}" ] && continue
    both="$(comm -12 <(rule_ids "${REPO_RULES}") <(rule_ids "${f}") | tr '\n' ' ')"
    [ -n "${both// /}" ] && CONFLICTS="${CONFLICTS}${both}в ${f}; "
done
shopt -u nullglob
[ -z "${CONFLICTS}" ] || die "ID правил репозитория уже заняты в других файлах: ${CONFLICTS}"
ok "Конфликтов правил и декодеров нет."

# 4. Backup of every file this script may change
info "==> 1. Создание резервной копии рабочей конфигурации..."
mkdir -p "${OSSEC_DIR}/backup"
BACKUP_DIR="$(mktemp -d "${OSSEC_DIR}/backup/setup-${TIMESTAMP}-XXXX")"   # mktemp: mode 0700
MANAGED_FILES=(
    "${OSSEC_DIR}/etc/ossec.conf"
    "${SRV_RULES}"
    "${SRV_DECODER}"
    "${OSSEC_DIR}/etc/local_internal_options.conf"
    "${OSSEC_DIR}/integrations/custom-telegram"
    "${OSSEC_DIR}/integrations/custom-telegram.py"
)
: > "${BACKUP_DIR}/MANIFEST"
for f in "${MANAGED_FILES[@]}"; do
    if [ -e "${f}" ]; then
        cp -a "${f}" "${BACKUP_DIR}/$(basename "${f}")"
        echo "present ${f}" >> "${BACKUP_DIR}/MANIFEST"
    else
        echo "absent ${f}" >> "${BACKUP_DIR}/MANIFEST"
    fi
done
ok "Резервная копия: ${BACKUP_DIR}"

restore_backup() {
    local state path
    while read -r state path; do
        case "${state}" in
            present) cp -a "${BACKUP_DIR}/$(basename "${path}")" "${path}" ;;
            absent)  rm -f "${path}" ;;
        esac
    done < "${BACKUP_DIR}/MANIFEST"
    warn "Конфигурация восстановлена из ${BACKUP_DIR}"
}

# write $2 into $1 keeping owner/mode/inode of an existing file
replace_content() {
    local dst=$1 src=$2
    if [ -e "${dst}" ]; then cat "${src}" > "${dst}"; else install -o root -g wazuh -m 0640 "${src}" "${dst}"; fi
}

# 5. Stale .restart flag from a crashed restart (only if older than 5 minutes)
info "==> 2. Проверка и очистка зависших файлов состояния..."
find "${OSSEC_DIR}/var/run" -maxdepth 1 -name '.restart' -mmin +5 -delete 2>/dev/null || true

TMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TMP_DIR}"' EXIT

# 6. Internal options: managed block, other lines are kept
info "==> 3. Тюнинг очередей (${OSSEC_DIR}/etc/local_internal_options.conf)..."
"${PYTHON}" "${SCRIPT_DIR}/lib/ossec_conf.py" internal-options \
    --conf "${OSSEC_DIR}/etc/local_internal_options.conf" \
    --source "${SCRIPT_DIR}/server-config/local_internal_options.conf" \
    --out "${TMP_DIR}/local_internal_options.conf"
replace_content "${OSSEC_DIR}/etc/local_internal_options.conf" "${TMP_DIR}/local_internal_options.conf"

# 7. Telegram integration executables
info "==> 4. Развертывание исполняемых файлов Telegram-интеграции..."
mkdir -p "${OSSEC_DIR}/integrations"
install -o root -g wazuh -m 0750 "${SCRIPT_DIR}/integrations/telegram/custom-telegram"    "${OSSEC_DIR}/integrations/custom-telegram"
install -o root -g wazuh -m 0750 "${SCRIPT_DIR}/integrations/telegram/custom-telegram.py" "${OSSEC_DIR}/integrations/custom-telegram.py"

# 8. ossec.conf
info "==> 5. Безопасное конфигурирование ${OSSEC_DIR}/etc/ossec.conf..."
export TELEGRAM_BOT_TOKEN TELEGRAM_CHAT_ID
"${PYTHON}" "${SCRIPT_DIR}/lib/ossec_conf.py" ossec --conf "${OSSEC_DIR}/etc/ossec.conf" --out "${TMP_DIR}/ossec.conf"
replace_content "${OSSEC_DIR}/etc/ossec.conf" "${TMP_DIR}/ossec.conf"
ok "ossec.conf обновлён."

# 9. Rules and decoders
info "==> 6. Установка правил обнаружения и фильтрации..."
for pair in "${REPO_RULES}|${SRV_RULES}" "${REPO_DECODER}|${SRV_DECODER}"; do
    replace_content "${pair##*|}" "${pair%%|*}"
done

# 10. Validation BEFORE restart
info "==> 7. Проверка конфигурации до перезапуска..."
validation_failed() {
    echo -e "${RED}[FAIL] $1. Выполняю автоматический откат (служба не перезапускалась)...${NC}" >&2
    restore_backup
    exit 1
}
for d in wazuh-analysisd wazuh-remoted; do
    help="$("${OSSEC_DIR}/bin/${d}" -h 2>&1 || true)"
    if grep -qE '^[[:space:]]*-t[[:space:]]' <<<"${help}"; then
        "${OSSEC_DIR}/bin/${d}" -t >"${TMP_DIR}/${d}.log" 2>&1 || { cat "${TMP_DIR}/${d}.log" >&2; validation_failed "${d} -t обнаружил ошибку"; }
        ok "${d} -t: конфигурация корректна."
    fi
done
if "${OSSEC_DIR}/bin/wazuh-control" status 2>/dev/null | grep -q 'wazuh-analysisd is running'; then
    "${PYTHON}" "${SCRIPT_DIR}/tests/run_logtest.py" --logtest "${OSSEC_DIR}/bin/wazuh-logtest" \
        --cases "${SCRIPT_DIR}/tests/cases.json" --skip-tag eventchannel \
        || validation_failed "тестовые события сработали не на те правила"
    ok "Тестовые события обработаны ожидаемыми правилами."
else
    warn "wazuh-analysisd не запущен: проверка wazuh-logtest пропущена."
fi

# 11. Restart + health check
info "==> 8. Перезапуск службы wazuh-manager..."
manager_healthy() {
    local status
    systemctl is-active --quiet wazuh-manager || return 1
    status="$("${OSSEC_DIR}/bin/wazuh-control" status 2>/dev/null || true)"
    grep -q 'wazuh-analysisd is running' <<<"${status}" && grep -q 'wazuh-remoted is running' <<<"${status}"
}
RESTART_OK=false
if systemctl restart wazuh-manager; then
    for _ in $(seq 1 45); do
        if manager_healthy; then RESTART_OK=true; break; fi
        sleep 2
    done
fi
if [ "${RESTART_OK}" != true ]; then
    echo -e "${RED}[FAIL] wazuh-manager не перешёл в рабочее состояние за 90 секунд.${NC}" >&2
    "${OSSEC_DIR}/bin/wazuh-control" status >&2 || true
    tail -n 30 "${OSSEC_DIR}/logs/ossec.log" | grep -E 'ERROR|CRITICAL' >&2 || true
    restore_backup
    systemctl restart wazuh-manager || true
    die "Изменения откатаны. Подробности: ${OSSEC_DIR}/logs/ossec.log"
fi
ok "wazuh-manager работает (analysisd, remoted запущены)."

# 12. Optional OpenSearch ISM retention policy
ISM_STATUS="пропущено (пароль Indexer не задан)"
if [ -n "${INDEXER_PASSWORD}" ]; then
    info "==> 9. Применение политики хранения индексов (ISM)..."
    CA="/etc/wazuh-indexer/certs/root-ca.pem"
    TLS_OPT=(--cacert "${CA}")
    [ -f "${CA}" ] || { TLS_OPT=(-k); warn "${CA} не найден: проверка сертификата Indexer отключена."; }
    # the password is passed through a curl config on a pipe, not on the command line
    CODE="$(printf 'user = "admin:%s"\n' "${INDEXER_PASSWORD}" | curl -sS "${TLS_OPT[@]}" -K - \
        -o "${TMP_DIR}/ism.json" -w '%{http_code}' -X PUT "https://localhost:9200/_plugins/_ism/policies/wazuh_alerts_policy" \
        -H "Content-Type: application/json" -d @"${SCRIPT_DIR}/server-config/indexer_ism_policy.json" || echo 000)"
    case "${CODE}" in
        200|201) ISM_STATUS="применена"; ok "ISM-политика применена (действует для новых индексов)." ;;
        409)     ISM_STATUS="уже существует"; warn "ISM-политика уже существует (изменение — через Dashboard: Index Management)." ;;
        *)       ISM_STATUS="ошибка (HTTP ${CODE})"; warn "ISM-политика не применена: HTTP ${CODE}. $(head -c 300 "${TMP_DIR}/ism.json" 2>/dev/null)" ;;
    esac
fi

# 13. Verification alert to Telegram
info "==> 10. Отправка подтверждающего алерта в Telegram..."
TEST_ALERT_FILE="$(mktemp "${TMP_DIR}/alert.XXXXXX.json")"
cat << EOFTALERT > "${TEST_ALERT_FILE}"
{
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%S.000+0000)",
  "rule": {"level": 10, "id": "000000", "description": "Wazuh SIEM: настройка выполнена, оповещения уровня 10+ активны."},
  "agent": {"id": "000", "name": "$(hostname)", "ip": "${WAZUH_SERVER_IP}"},
  "full_log": "setup.sh verification message"
}
EOFTALERT
TG_STATUS="отправлено"
WAZUH_TELEGRAM_NO_FLOOD=1 "${OSSEC_DIR}/integrations/custom-telegram" "${TEST_ALERT_FILE}" "${TELEGRAM_CHAT_ID}" "${TELEGRAM_BOT_TOKEN}" \
    || { TG_STATUS="НЕ отправлено"; warn "Проверьте токен/Chat ID и доступ к api.telegram.org."; }

echo -e "\n${GREEN}======================================================================${NC}"
echo -e "${BOLD}${GREEN}  Wazuh SIEM настроен${NC}"
echo -e "  wazuh-manager:          работает"
echo -e "  Тестовое сообщение:     ${TG_STATUS}"
echo -e "  ISM-политика:           ${ISM_STATUS}"
echo -e "  Резервная копия:        ${BACKUP_DIR}"
echo -e "${GREEN}======================================================================${NC}"
