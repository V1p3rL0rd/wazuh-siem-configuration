#!/usr/bin/env bash
# ==============================================================================
# lib/env.sh - shared helpers for the single project-level .env file.
# Source it:  source "${REPO_ROOT}/lib/env.sh"
#   env_init   FILE                      create FILE (chmod 600) if missing
#   env_get    FILE KEY                  print value ("" if unset)
#   env_set    FILE KEY VALUE            update/append KEY, keep all other lines
#   env_prompt FILE KEY DESC [DEFAULT] [MODE] [REGEX]
#              MODE: plain (default) | secret (no echo) | optional
#              Keeps an already valid value; otherwise asks interactively,
#              saves it to FILE and exports KEY. Non-interactive run with a
#              missing value and no DEFAULT is a hard error.
# Values may not contain whitespace, quotes, backslash, '$' or '#': they are
# read by bash, docker compose and python without quoting rules in common.
# ==============================================================================

env_init() {
    local f="$1"
    if [ ! -f "${f}" ]; then
        ( umask 077; : > "${f}" )
    fi
    chmod 600 "${f}" 2>/dev/null || true
}

env_get() {
    local f="$1" k="$2" v
    [ -f "${f}" ] || { printf ''; return 0; }
    v=$(grep -E "^[[:space:]]*${k}=" "${f}" | tail -n1 | cut -d'=' -f2- | tr -d '\r' || true)
    v="${v#"${v%%[![:space:]]*}"}"
    v="${v%"${v##*[![:space:]]}"}"
    v="${v#\"}"; v="${v%\"}"; v="${v#\'}"; v="${v%\'}"
    printf '%s' "${v}"
}

env_set() {
    local f="$1" k="$2" v="$3" tmp
    env_init "${f}"
    tmp="$(mktemp "${f}.XXXXXX")"
    K="${k}" V="${v}" awk '
        BEGIN { k = ENVIRON["K"]; v = ENVIRON["V"]; done = 0 }
        $0 ~ "^[[:space:]]*" k "=" { if (!done) { print k "=" v; done = 1 } ; next }
        { print }
        END { if (!done) print k "=" v }
    ' "${f}" > "${tmp}"
    chmod 600 "${tmp}"
    mv "${tmp}" "${f}"
}

env_is_placeholder() {
    case "$1" in
        ""|*"<"*|*">"*|*ВСТАВЬТЕ*|*changeme*|*CHANGE_ME*) return 0 ;;
    esac
    return 1
}

env_value_ok() {
    local v="$1" re="${2:-}"
    if [[ "${v}" =~ [[:space:]\"\'\\\$#] ]]; then
        echo "  [!] Недопустимые символы (пробел, кавычки, \\, \$, #)." >&2
        return 1
    fi
    if [ -n "${re}" ] && ! [[ "${v}" =~ ${re} ]]; then
        echo "  [!] Неверный формат значения." >&2
        return 1
    fi
    return 0
}

env_prompt() {
    local f="$1" k="$2" desc="$3" def="${4:-}" mode="${5:-plain}" re="${6:-}"
    local cur val
    env_init "${f}"
    cur="$(env_get "${f}" "${k}")"
    if ! env_is_placeholder "${cur}" && env_value_ok "${cur}" "${re}" 2>/dev/null; then
        printf -v "${k}" '%s' "${cur}"; export "${k?}"
        return 0
    fi

    if [ ! -t 0 ]; then
        if [ -n "${def}" ]; then
            val="${def}"
        elif [ "${mode}" = "optional" ]; then
            return 0
        else
            echo "[ERROR] ${k} не задан в ${f}, а ввод неинтерактивный. Задайте его вручную." >&2
            return 1
        fi
    else
        while :; do
            if [ "${mode}" = "secret" ]; then
                read -r -s -p "${desc}${def:+ [по умолчанию: ${def}]}: " val; echo >&2
            else
                read -r -p "${desc}${def:+ [${def}]}${mode:+}: " val
            fi
            val="${val:-${def}}"
            if [ -z "${val}" ]; then
                [ "${mode}" = "optional" ] && return 0
                echo "  [!] Значение обязательно." >&2
                continue
            fi
            env_value_ok "${val}" "${re}" && break
        done
    fi
    env_set "${f}" "${k}" "${val}"
    printf -v "${k}" '%s' "${val}"; export "${k?}"
}
