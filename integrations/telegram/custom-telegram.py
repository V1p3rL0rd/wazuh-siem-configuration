#!/usr/bin/env python3
"""
Wazuh SIEM - Telegram Integration Script
Processes Wazuh alert JSON files and sends formatted security notifications to Telegram.
Filters alerts >= level 10, formats MITRE ATT&CK information, and prevents alert storms.
"""

import sys
import os
import json
import urllib.request
import urllib.parse
import html
import time
import hashlib
import ssl
from datetime import datetime

# Anti-flood cache to prevent Telegram rate-limiting (429) during incident spikes
FLOOD_CACHE_FILE = "/var/ossec/var/run/wazuh_telegram_flood_cache.json"
if not os.path.isdir("/var/ossec/var/run"):
    FLOOD_CACHE_FILE = "/tmp/wazuh_telegram_flood_cache.json"
FLOOD_WINDOW_SECONDS = 15  # Deduplicate identical (rule_id + agent_id) alerts within 15s
MAX_CACHE_ENTRIES = 500

def get_ssl_context() -> ssl.SSLContext:
    """Create SSL context that supports corporate proxies and TLS interception."""
    ctx = ssl.create_default_context()
    for ca_path in ['/etc/ssl/certs/ca-certificates.crt', '/etc/pki/tls/certs/ca-bundle.crt', '/etc/ssl/cert.pem']:
        if os.path.exists(ca_path):
            try:
                ctx.load_verify_locations(cafile=ca_path)
            except Exception:
                pass
    # Disable strict hostname and certificate verification for environments with SSL MITM inspection
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def get_severity_badge(level: int) -> str:
    if level >= 14:
        return "🔥 CRITICAL (Level {})".format(level)
    elif level >= 12:
        return "🚨 HIGH (Level {})".format(level)
    elif level >= 10:
        return "⚠️ WARNING (Level {})".format(level)
    return "ℹ️ INFO (Level {})".format(level)

def is_flooded(rule_id: str, agent_id: str) -> bool:
    """Check if the same alert from the same agent was sent recently."""
    now = time.time()
    cache = {}
    if os.path.exists(FLOOD_CACHE_FILE):
        try:
            with open(FLOOD_CACHE_FILE, "r") as f:
                cache = json.load(f)
        except Exception:
            cache = {}

    # Purge expired cache entries
    cache = {k: v for k, v in cache.items() if now - v.get("timestamp", 0) < FLOOD_WINDOW_SECONDS}

    alert_sig = "{}:{}".format(rule_id, agent_id)
    if alert_sig in cache:
        cache[alert_sig]["count"] += 1
        try:
            with open(FLOOD_CACHE_FILE, "w") as f:
                json.dump(cache, f)
        except Exception:
            pass
        return True

    cache[alert_sig] = {"timestamp": now, "count": 1}
    # Keep cache size bounded
    if len(cache) > MAX_CACHE_ENTRIES:
        oldest = sorted(cache.keys(), key=lambda k: cache[k]["timestamp"])[:50]
        for k in oldest:
            cache.pop(k, None)

    try:
        with open(FLOOD_CACHE_FILE, "w") as f:
            json.dump(cache, f)
    except Exception:
        pass

    return False

def format_telegram_message(alert: dict) -> str:
    if not isinstance(alert, dict):
        alert = {}

    rule = alert.get("rule") or {}
    level = rule.get("level", 0)
    rule_id = rule.get("id", "N/A")
    description = rule.get("description", "Security Event Detected")

    agent = alert.get("agent") or {}
    agent_name = agent.get("name", "Wazuh Server")
    agent_id = agent.get("id", "000")
    agent_ip = agent.get("ip", "Local")

    timestamp = alert.get("timestamp", datetime.utcnow().isoformat())

    # MITRE ATT&CK extraction (defensive against None or non-list)
    mitre = rule.get("mitre") or {}
    mitre_ids = mitre.get("id") or []
    if isinstance(mitre_ids, str):
        mitre_ids = [mitre_ids]
    mitre_tactics = mitre.get("tactic") or []
    if isinstance(mitre_tactics, str):
        mitre_tactics = [mitre_tactics]
    mitre_techniques = mitre.get("technique") or []
    if isinstance(mitre_techniques, str):
        mitre_techniques = [mitre_techniques]

    mitre_text = ""
    if mitre_ids or mitre_tactics:
        tactic_str = ", ".join(mitre_tactics) if mitre_tactics else "N/A"
        tech_str = ", ".join(mitre_techniques) if mitre_techniques else "N/A"
        id_str = ", ".join(mitre_ids) if mitre_ids else "N/A"
        mitre_text = (
            f"\n🎯 <b>MITRE ATT&amp;CK:</b>\n"
            f"• <b>Tactic:</b> {html.escape(tactic_str)}\n"
            f"• <b>Technique:</b> {html.escape(tech_str)} ({html.escape(id_str)})\n"
        )

    # Contextual data (safe against None values)
    data = alert.get("data") or {}
    context_lines = []

    # Windows Event Log data
    win = data.get("win") if isinstance(data, dict) else {}
    win_data = (win.get("eventdata") or {}) if isinstance(win, dict) else {}
    if isinstance(win_data, dict):
        if win_data.get("targetUserName"):
            context_lines.append(f"• <b>User:</b> <code>{html.escape(str(win_data.get('targetUserName')))}</code>")
        if win_data.get("image"):
            context_lines.append(f"• <b>Process:</b> <code>{html.escape(str(win_data.get('image')))}</code>")
        if win_data.get("commandLine"):
            cmd = str(win_data.get("commandLine"))[:250]
            context_lines.append(f"• <b>CommandLine:</b> <code>{html.escape(cmd)}</code>")
        if win_data.get("sourceIp"):
            context_lines.append(f"• <b>Source IP:</b> <code>{html.escape(str(win_data.get('sourceIp')))}</code>")

    # Linux / Syslog / Auditd data
    if isinstance(data, dict):
        src_ip = data.get("srcip") or alert.get("srcip")
        if src_ip:
            context_lines.append(f"• <b>Source IP:</b> <code>{html.escape(str(src_ip))}</code>")
        src_user = data.get("srcuser") or alert.get("srcuser")
        if src_user:
            context_lines.append(f"• <b>User:</b> <code>{html.escape(str(src_user))}</code>")
        audit = data.get("audit") or {}
        if isinstance(audit, dict) and audit.get("command"):
            context_lines.append(f"• <b>Audit Command:</b> <code>{html.escape(str(audit.get('command')))}</code>")

    context_str = ""
    if context_lines:
        context_str = "\n🔎 <b>Details:</b>\n" + "\n".join(context_lines) + "\n"

    # Full log snippet (truncated for Telegram 4096 character limit)
    full_log = alert.get("full_log", "")
    log_snippet = ""
    if full_log:
        trimmed_log = str(full_log).strip()[:350]
        log_snippet = f"\n📄 <b>Log Snippet:</b>\n<pre>{html.escape(trimmed_log)}</pre>\n"

    badge = get_severity_badge(level)

    message = (
        f"{badge}\n\n"
        f"🛡️ <b>Rule:</b> [{rule_id}] {html.escape(str(description))}\n"
        f"🖥️ <b>Host:</b> {html.escape(str(agent_name))} (ID: <code>{agent_id}</code> | IP: <code>{agent_ip}</code>)\n"
        f"⏰ <b>Time:</b> {html.escape(str(timestamp))}\n"
        f"{mitre_text}"
        f"{context_str}"
        f"{log_snippet}"
    )

    return message

def send_telegram_alert(bot_token: str, chat_id: str, message: str) -> bool:
    telegram_url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": chat_id,
        "text": message,
        "parse_mode": "HTML",
        "disable_web_page_preview": True
    }

    req_data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        telegram_url,
        data=req_data,
        headers={"Content-Type": "application/json"}
    )

    ctx = get_ssl_context()
    try:
        with urllib.request.urlopen(req, context=ctx, timeout=10) as response:
            return response.status == 200
    except Exception as e:
        sys.stderr.write(f"Failed to send alert to Telegram: {e}\n")
        return False

def main():
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: custom-telegram.py <alert_file> [api_key] [hook_url]\n")
        sys.exit(1)

    alert_filepath = sys.argv[1]

    # In ossec.conf:
    # <api_key> is passed as sys.argv[2] (e.g. Chat ID or Bot Token)
    # <hook_url> is passed as sys.argv[3] (e.g. https://api.telegram.org/bot<TOKEN>/sendMessage or chat ID)
    # We also allow environment variables for clean container setups
    bot_token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")

    if len(sys.argv) >= 3 and sys.argv[2] and not chat_id:
        chat_id = sys.argv[2]

    if len(sys.argv) >= 4 and sys.argv[3]:
        hook_arg = sys.argv[3]
        if "api.telegram.org/bot" in hook_arg:
            # Extracted token from hook_url if configured as https://api.telegram.org/bot<TOKEN>/sendMessage
            parts = hook_arg.split("api.telegram.org/bot")
            if len(parts) > 1:
                token_candidate = parts[1].split("/")[0]
                if token_candidate:
                    bot_token = token_candidate
        elif not bot_token:
            bot_token = hook_arg

    # Fallback: check .env files directly if arguments did not supply token or chat_id
    if not bot_token or not chat_id:
        for env_path in ['/home/sbra-admin/wazuh-siem/.env', '/home/sbra-admin/.env', '/var/ossec/etc/.env', './.env']:
            if os.path.exists(env_path):
                try:
                    with open(env_path, 'r', encoding='utf-8') as ef:
                        for line in ef:
                            line = line.strip()
                            if not bot_token and line.startswith('TELEGRAM_BOT_TOKEN='):
                                bot_token = line.split('=', 1)[1].strip().strip('"\'')
                            elif not chat_id and line.startswith('TELEGRAM_CHAT_ID='):
                                chat_id = line.split('=', 1)[1].strip().strip('"\'')
                except Exception:
                    pass
            if bot_token and chat_id:
                break

    if not bot_token or not chat_id:
        sys.stderr.write("Telegram bot token or chat ID is missing. Check ossec.conf or ENV variables.\n")
        sys.exit(1)

    try:
        with open(alert_filepath, "r", encoding="utf-8") as f:
            alert = json.load(f)
    except Exception as e:
        sys.stderr.write(f"Error reading alert file {alert_filepath}: {e}\n")
        sys.exit(1)

    rule = alert.get("rule", {})
    level = rule.get("level", 0)

    # Double check alert level (configured in ossec.conf <level>10</level>)
    if level < 10:
        sys.exit(0)

    rule_id = str(rule.get("id", "0"))
    agent_id = str(alert.get("agent", {}).get("id", "0"))

    # Flood suppression
    if is_flooded(rule_id, agent_id):
        sys.stderr.write(f"Alert [{rule_id}] on agent [{agent_id}] suppressed by flood control.\n")
        sys.exit(0)

    formatted_msg = format_telegram_message(alert)
    send_telegram_alert(bot_token, chat_id, formatted_msg)

if __name__ == "__main__":
    main()
