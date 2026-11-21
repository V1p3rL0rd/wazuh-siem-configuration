#!/usr/bin/env python3
"""Run KSC sample events through wazuh-logtest and check decoder/rule results.

Usage (on the Wazuh manager, as root):
    python3 tests/run_logtest.py
    python3 tests/run_logtest.py --logtest /var/ossec/bin/wazuh-logtest --cases tests/cases.json -v

Only the Python standard library is used, so it runs both with the system
python3 and with Wazuh's embedded /var/ossec/framework/python/bin/python3.

Exit codes: 0 all cases passed, 1 at least one case failed, 2 runtime error.
"""
import argparse
import json
import os
import re
import subprocess
import sys

PHASE1 = re.compile(r"^\*\*Phase 1: Completed pre-decoding\.", re.M)
PHASE2 = re.compile(r"^\*\*Phase 2: Completed decoding\.", re.M)
PHASE3 = re.compile(r"^\*\*Phase 3: Completed filtering \(rules\)\.", re.M)
KV = re.compile(r"^\s+([\w.\-]+): '(.*)'\s*$", re.M)


def parse_output(text):
    """Split wazuh-logtest output into per-event result dicts."""
    results = []
    starts = [m.start() for m in PHASE1.finditer(text)]
    for i, start in enumerate(starts):
        chunk = text[start:starts[i + 1] if i + 1 < len(starts) else len(text)]
        res = {"decoder": None, "fields": {}, "rule_id": None, "level": None, "description": None,
               "alert": "**Alert to be generated." in chunk}
        p2 = PHASE2.search(chunk)
        p3 = PHASE3.search(chunk)
        if p2:
            section = chunk[p2.end():p3.start() if p3 else len(chunk)]
            for key, value in KV.findall(section):
                if key == "name":
                    res["decoder"] = value
                else:
                    res["fields"][key] = value
        if p3:
            section = chunk[p3.end():]
            kv = dict(KV.findall(section))
            res["rule_id"] = kv.get("id")
            res["level"] = int(kv["level"]) if kv.get("level", "").isdigit() else None
            res["description"] = kv.get("description")
        results.append(res)
    return results


def load_event(base, spec):
    with open(os.path.join(base, spec["file"]), encoding="utf-8") as f:
        line = f.read().strip("\r\n")
    for old, new in spec.get("replace", {}).items():
        line = line.replace(old, new)
    if "\n" in line:
        raise ValueError("%s: sample must be a single line" % spec["file"])
    return line


def check(res, exp):
    """Return a list of human-readable mismatches between a result and an expectation."""
    errors = []
    if "decoder" in exp and res["decoder"] != exp["decoder"]:
        errors.append("decoder: expected %r, got %r" % (exp["decoder"], res["decoder"]))
    if "decoder_not" in exp and res["decoder"] == exp["decoder_not"]:
        errors.append("decoder must not be %r" % exp["decoder_not"])
    if "rule_id" in exp and res["rule_id"] != str(exp["rule_id"]):
        errors.append("rule: expected %s, got %s" % (exp["rule_id"], res["rule_id"]))
    if "level" in exp and res["level"] != exp["level"]:
        errors.append("level: expected %s, got %s" % (exp["level"], res["level"]))
    if "alert" in exp and res["alert"] != exp["alert"]:
        errors.append("alert: expected %s, got %s" % (exp["alert"], res["alert"]))
    for key, value in exp.get("fields", {}).items():
        got = res["fields"].get(key)
        if got != value:
            errors.append("field %s: expected %r, got %r" % (key, value, got))
    return errors


def run_case(logtest, base, case, timeout):
    events = [load_event(base, e) for e in case["events"]]
    proc = subprocess.run([logtest], input="\n".join(events) + "\n", stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, encoding="utf-8", errors="replace", timeout=timeout)
    results = parse_output(proc.stdout)
    if len(results) != len(events):
        return ["logtest returned %d results for %d events (exit %d). Output:\n%s"
                % (len(results), len(events), proc.returncode, proc.stdout[-2000:])], results
    errors = []
    if "expect" in case:
        errors += check(results[-1], case["expect"])
    if "expect_any" in case:
        if not any(not check(r, case["expect_any"]) for r in results):
            errors.append("no event matched %s; rules seen: %s"
                          % (case["expect_any"], [r["rule_id"] for r in results]))
    if "expect_none" in case:
        bad = [i + 1 for i, r in enumerate(results) if not check(r, case["expect_none"])]
        if bad:
            errors.append("events %s unexpectedly matched %s" % (bad, case["expect_none"]))
    return errors, results


def main(argv=None):
    here = os.path.dirname(os.path.abspath(__file__))
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--logtest", default="/var/ossec/bin/wazuh-logtest")
    p.add_argument("--cases", default=os.path.join(here, "cases.json"))
    p.add_argument("--timeout", type=int, default=120)
    p.add_argument("-v", "--verbose", action="store_true", help="print rule/level/description per event")
    p.add_argument("--skip-tag", action="append", default=[], help="skip cases with this tag (repeatable)")
    a = p.parse_args(argv)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(errors="replace")  # C/POSIX locale on servers must not crash on Cyrillic

    try:
        with open(a.cases, encoding="utf-8") as f:
            cases = json.load(f)["cases"]
    except (OSError, ValueError, KeyError) as e:
        print("error: cannot load cases: %s" % e, file=sys.stderr)
        return 2
    if not os.access(a.logtest, os.X_OK):
        print("error: %s not found or not executable (run as root on the Wazuh manager)" % a.logtest,
              file=sys.stderr)
        return 2

    base = os.path.dirname(os.path.abspath(a.cases))
    failed = skipped = 0
    for case in cases:
        if set(case.get("tags", [])) & set(a.skip_tag):
            print("[SKIP] %s" % case["name"])
            skipped += 1
            continue
        try:
            errors, results = run_case(a.logtest, base, case, a.timeout)
        except (OSError, ValueError, subprocess.TimeoutExpired) as e:
            errors, results = ["runtime error: %s" % e], []
        status = "PASS" if not errors else "FAIL"
        failed += bool(errors)
        print("[%s] %s" % (status, case["name"]))
        if a.verbose or errors:
            for i, r in enumerate(results, 1):
                print("       event %d: decoder=%s rule=%s level=%s alert=%s | %s"
                      % (i, r["decoder"], r["rule_id"], r["level"], r["alert"], r["description"]))
        for e in errors:
            print("       - %s" % e)
    print("\n%d/%d cases passed, %d skipped" % (len(cases) - failed - skipped, len(cases) - skipped, skipped))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
