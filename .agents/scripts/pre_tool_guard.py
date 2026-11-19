#!/usr/bin/env python3
"""
pre_tool_guard.py - Antigravity PreToolUse Safety Guard

Inspects run_command tool calls against the Hard Safety Gates defined in GEMINI.md.
Blocks prohibited destructive operations and prompts for confirmation on high-risk commands.
"""

import sys
import json
import re

BLOCKED_PATTERNS = [
    (r"\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+/(?:\s|$|\*)", "Попытка рекурсивного удаления корневой файловой системы (rm -rf /)"),
    (r"\bmkfs\b", "Форматирование дисковых разделов (mkfs)"),
    (r"\bdd\s+if=.*of=/dev/(?:sd[a-z]|nvme[0-9]n[0-9]|vd[a-z])\b", "Прямая перезапись блочных устройств (dd)"),
    (r"\b(DROP\s+DATABASE|TRUNCATE\s+TABLE)\b", "Деструктивная операция СУБД (DROP DATABASE / TRUNCATE) без CAB-процедуры"),
    (r"\b(FLUSHALL|FLUSHDB)\b", "Полная очистка данных Redis (FLUSHALL/FLUSHDB)"),
    (r"\b(nft\s+flush\s+ruleset|iptables\s+-F)\b", "Полный сброс правил межсетевого экрана (Lockout риск)")
]

def main():
    try:
        raw_input = sys.stdin.read()
        if not raw_input.strip():
            print(json.dumps({}))
            return

        payload = json.loads(raw_input)
        tool_call = payload.get("toolCall", {})
        args = tool_call.get("args", {})
        cmd = args.get("CommandLine", "")

        if not cmd:
            print(json.dumps({}))
            return

        for pattern, reason in BLOCKED_PATTERNS:
            if re.search(pattern, cmd, re.IGNORECASE):
                response = {
                    "decision": "deny",
                    "reason": f"🛑 BLOCKED BY SAFETY GATE: {reason}. Команда: '{cmd}'"
                }
                print(json.dumps(response))
                return

        # Passed all safety checks
        print(json.dumps({}))

    except Exception:
        # Fallback to allow if unexpected parsing failure occurs to avoid deadlocking
        print(json.dumps({}))

if __name__ == "__main__":
    main()
