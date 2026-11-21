#!/usr/bin/env python3
"""Unit tests that do not need Wazuh.

    python3 -m unittest discover -s tests -p 'test_*.py' -v
"""
import importlib.util
import json
import os
import re
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.join(ROOT, "lib"))

import ossec_conf  # noqa: E402
import run_logtest  # noqa: E402

spec = importlib.util.spec_from_file_location("tg", os.path.join(ROOT, "integrations", "telegram", "custom-telegram.py"))
tg = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tg)

OSSEC = """<ossec_config>
  <global>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
  </global>

  <!-- Telegram Alerting Integration (Level >= 10) -->
  <integration>
    <name>custom-telegram</name>
    <hook_url>https://api.telegram.org/bot1:old/sendMessage</hook_url>
    <api_key>-1</api_key>
    <level>10</level>
    <alert_format>json</alert_format>
  </integration>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <remote>
    <connection>syslog</connection>
    <port>514</port>
    <protocol>tcp</protocol>
    <allowed-ips>192.0.2.5/32</allowed-ips>
  </remote>
</ossec_config>
"""


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class OssecConfTest(unittest.TestCase):
    def setUp(self):
        self.new = ossec_conf.edit_ossec(OSSEC, "123:abc", "-100")

    def test_queue_size_only_in_secure_remote(self):
        blocks = re.findall(r"<remote>.*?</remote>", self.new, re.S)
        secure = [b for b in blocks if "secure" in b]
        syslog = [b for b in blocks if "syslog" in b]
        self.assertIn("<queue_size>131072</queue_size>", secure[0])
        self.assertNotIn("queue_size", syslog[0])  # would stop wazuh-remoted

    def test_logall_disabled(self):
        self.assertIn("<logall>no</logall>", self.new)
        self.assertIn("<logall_json>no</logall_json>", self.new)

    def test_single_integration_with_new_credentials(self):
        self.assertEqual(self.new.count("<name>custom-telegram</name>"), 1)
        self.assertIn("bot123:abc/sendMessage", self.new)
        self.assertNotIn("bot1:old", self.new)

    def test_idempotent(self):
        self.assertEqual(ossec_conf.edit_ossec(self.new, "123:abc", "-100"), self.new)

    def test_internal_options_managed_block(self):
        opts = ossec_conf.read_options(os.path.join(ROOT, "server-config", "local_internal_options.conf"))
        old = "remoted.rqueue_size=100000\nanalysisd.rqueue_size=100000\nintegrator.max_threads=4\ncustom.option=1\n"
        new = ossec_conf.edit_internal_options(old, opts)
        self.assertNotIn("rqueue_size", new)
        self.assertNotIn("integrator.max_threads", new)
        self.assertIn("custom.option=1", new)
        self.assertEqual(new.count(ossec_conf.OPT_BEGIN), 1)
        self.assertEqual(ossec_conf.edit_internal_options(new, opts), new)

    def test_reference_options_exist_in_wazuh(self):
        # every option must be one of the documented Wazuh 4.x internal options
        known = {"analysisd.decode_event_queue_size", "analysisd.decode_syscheck_queue_size",
                 "analysisd.decode_winevt_queue_size", "analysisd.alerts_queue_size", "monitord.keep_log_days"}
        opts = ossec_conf.read_options(os.path.join(ROOT, "server-config", "local_internal_options.conf"))
        self.assertTrue({o.split("=")[0] for o in opts} <= known)


class TelegramTest(unittest.TestCase):
    def alert(self, host):
        return {"rule": {"id": "100701", "level": 10, "description": "x"}, "agent": {"id": "000", "name": "m"},
                "data": {"ksc": {"host": host, "event_type": "GNRL_EV_VIRUS_FOUND"}}}

    def test_signature_separates_hosts_behind_one_agent(self):
        self.assertNotEqual(tg.flood_signature(self.alert("PC-1")), tg.flood_signature(self.alert("PC-2")))
        self.assertEqual(tg.flood_signature(self.alert("PC-1")), tg.flood_signature(self.alert("PC-1")))

    def test_tls_verification_enabled(self):
        ctx = tg.get_ssl_context()
        self.assertTrue(ctx.check_hostname)
        self.assertEqual(ctx.verify_mode, tg.ssl.CERT_REQUIRED)

    def test_message_is_escaped(self):
        msg = tg.format_telegram_message({"rule": {"id": "1", "level": 12, "description": "<b>x</b>"},
                                          "agent": {"id": "<1>", "name": "a&b", "ip": "<ip>"}})
        self.assertNotIn("<b>x</b>", msg)
        self.assertIn("&lt;1&gt;", msg)
        self.assertIn("&lt;ip&gt;", msg)


class ParserTest(unittest.TestCase):
    def test_parse(self):
        res = run_logtest.parse_output(read(os.path.join(HERE, "fixtures", "logtest_output_sample.txt")))
        self.assertEqual([(r["rule_id"], r["level"], r["alert"]) for r in res], [("100022", 0, False), ("100010", 14, True)])
        self.assertEqual(res[0]["decoder"], "pam")


class RepoTest(unittest.TestCase):
    def test_rule_ids_unique_and_in_range(self):
        ids = re.findall(r'rule id="(\d+)"', read(os.path.join(ROOT, "rules-and-decoders", "local_rules.xml")))
        ids += re.findall(r'rule id="(\d+)"', read(os.path.join(ROOT, "rules-and-decoders", "ad_ds_rules.xml.optional")))
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(100000 <= int(i) <= 100099 for i in ids))

    def test_cases_reference_existing_samples(self):
        for case in json.loads(read(os.path.join(HERE, "cases.json")))["cases"]:
            for e in case["events"]:
                self.assertTrue(os.path.isfile(os.path.join(HERE, e["file"])), e["file"])


if __name__ == "__main__":
    unittest.main()
