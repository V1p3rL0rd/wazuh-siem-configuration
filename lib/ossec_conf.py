#!/usr/bin/env python3
"""Safe in-place edits of Wazuh manager configuration files used by setup.sh.

ossec.conf is not a single XML document (it may contain several <ossec_config>
roots), so it is edited as text with narrowly scoped regular expressions.

  ossec            --conf FILE --out FILE   (TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID from env)
      * <logall>/<logall_json> -> no
      * <queue_size>131072</queue_size> in SECURE <remote> blocks only
        (queue_size in a syslog <remote> makes wazuh-remoted refuse to start)
      * exactly one custom-telegram <integration> (level 10, json)
  internal-options --conf FILE --source FILE --out FILE
      * replaces/creates a managed block with the options from --source,
        keeps every other line, drops options known not to exist in Wazuh 4.x
"""
import argparse
import os
import re
import sys

QUEUE_SIZE = "131072"
OPT_BEGIN = "# BEGIN wazuh-siem-configuration (managed by setup.sh)"
OPT_END = "# END wazuh-siem-configuration"
# Written by earlier versions of setup.sh; they do not exist in Wazuh 4.x and are ignored by it.
OBSOLETE_OPTIONS = ("remoted.rqueue_size", "analysisd.rqueue_size", "integrator.max_threads",
                    "analysisd.memory_limit")


def tag(body, name):
    m = re.search(r"<%s>\s*(.*?)\s*</%s>" % (name, name), body, re.S)
    return m.group(1).strip() if m else None


def tune_remote(match):
    block = match.group(0)
    connection = (tag(block, "connection") or "secure").lower()
    if connection != "secure":
        return block  # syslog: queue_size is invalid there
    if "<queue_size>" in block:
        return re.sub(r"<queue_size>\s*\d+\s*</queue_size>", "<queue_size>%s</queue_size>" % QUEUE_SIZE, block)
    indent = re.search(r"\n([ \t]*)</remote>", block)
    inner = (indent.group(1) if indent else "  ") + "  "
    return re.sub(r"\n?([ \t]*)</remote>$",
                  lambda m: "\n%s<queue_size>%s</queue_size>\n%s</remote>" % (inner, QUEUE_SIZE, m.group(1)),
                  block)


def edit_ossec(text, bot_token, chat_id):
    text = re.sub(r"<logall>\s*(yes|no)\s*</logall>", "<logall>no</logall>", text)
    text = re.sub(r"<logall_json>\s*(yes|no)\s*</logall_json>", "<logall_json>no</logall_json>", text)
    text = re.sub(r"<remote>.*?</remote>", tune_remote, text, flags=re.S)

    # remove previous telegram integration (and its comment) to keep exactly one
    text = re.sub(r"\s*<!-- Telegram Alerting Integration[^\n]*-->[ \t]*", "", text)
    text = re.sub(r"\s*<integration>\s*<name>custom-telegram</name>.*?</integration>[ \t]*", "", text, flags=re.S)

    block = ("\n\n  <!-- Telegram Alerting Integration (Level >= 10) -->\n"
             "  <integration>\n"
             "    <name>custom-telegram</name>\n"
             "    <hook_url>https://api.telegram.org/bot%s/sendMessage</hook_url>\n"
             "    <api_key>%s</api_key>\n"
             "    <level>10</level>\n"
             "    <alert_format>json</alert_format>\n"
             "  </integration>") % (bot_token, chat_id)
    pos = text.find("</global>")
    if pos >= 0:
        pos += len("</global>")
    else:
        pos = text.find("</ossec_config>")
        if pos < 0:
            raise ValueError("no </global> and no </ossec_config>: not a Wazuh ossec.conf")
    return text[:pos] + block + text[pos:]


def read_options(path):
    opts = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                if not re.match(r"^[a-z_]+\.[a-z_]+=\S+$", line):
                    raise ValueError("bad option line in %s: %r" % (path, line))
                opts.append(line)
    return opts


def edit_internal_options(text, opts):
    managed = re.compile(re.escape(OPT_BEGIN) + r".*?" + re.escape(OPT_END) + r"\n?", re.S)
    text = managed.sub("", text)
    keys = {o.split("=", 1)[0] for o in opts}
    kept = []
    for line in text.splitlines():
        key = line.split("=", 1)[0].strip()
        if key in OBSOLETE_OPTIONS or key in keys:
            continue  # obsolete, or now set by the managed block
        kept.append(line)
    while kept and not kept[-1].strip():
        kept.pop()
    body = "\n".join(kept)
    return (body + "\n\n" if body else "") + OPT_BEGIN + "\n" + "\n".join(opts) + "\n" + OPT_END + "\n"


def main(argv=None):
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("ossec")
    s.add_argument("--conf", required=True)
    s.add_argument("--out", required=True)
    s = sub.add_parser("internal-options")
    s.add_argument("--conf", required=True)
    s.add_argument("--source", required=True)
    s.add_argument("--out", required=True)
    a = p.parse_args(argv)

    try:
        text = ""
        if os.path.exists(a.conf):
            with open(a.conf, encoding="utf-8") as f:
                text = f.read()
        if a.cmd == "ossec":
            token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
            chat = os.environ.get("TELEGRAM_CHAT_ID", "").strip()
            if not re.match(r"^[0-9]+:[A-Za-z0-9_-]+$", token) or not re.match(r"^-?[0-9]+$", chat):
                raise ValueError("TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID missing or malformed")
            new = edit_ossec(text, token, chat)
        else:
            new = edit_internal_options(text, read_options(a.source))
    except (OSError, ValueError) as e:
        print("[ERROR] %s" % e, file=sys.stderr)
        return 1
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(new)
    return 0


if __name__ == "__main__":
    sys.exit(main())
