# Testing and Rule Verification

Rules and decoders are verified with sample events in `tests/samples/` and expected results in `tests/cases.json`. The same tests run in CI on a real Wazuh manager (Docker) and in `setup.sh` before every restart.

---

## 1. Configuration and Syntax

```bash
sudo /var/ossec/bin/wazuh-analysisd -t     # rules, decoders, ossec.conf
sudo /var/ossec/bin/wazuh-remoted -t       # <remote> blocks
```

Both must exit with code 0.

---

## 2. Test Events

```bash
sudo python3 tests/run_logtest.py --skip-tag eventchannel -v
```

Windows cases are tagged `eventchannel`: on a manager, Windows rules match only events that arrive from agents through the event channel, so these cases are skipped there. CI runs them on a test manager where rule 60000 accepts the generic `json` decoder (the same approach as Wazuh's own ruleset tests).

Each case runs in its own `wazuh-logtest` session (frequency and correlation rules keep state within a case):

| Case | Expected |
|---|---|
| 8 failed SSH logons + success from the same IP | 100006, level 14 |
| SSH logon without failures | not 100006 |
| `rm -rf /var/log/...` | 100003, level 12 |
| auditd `key="sudoers_change"` | 100004, level 11 |
| auditd `key="kernel_modules"` | 100005, level 13 |
| cron session open | 100022, level 0 |
| Windows 1102 | 100010, level 14 |
| Windows 4732 to Administrators | 100011, level 12 |
| Windows 7045 | 100012, level 10 |
| PowerShell 4104 with `DownloadString ... IEX` | 100014, level 12 |
| Sysmon 1 `certutil -urlcache` | 100015, level 11 |
| 4688 `certutil -urlcache` | 100017, level 11 |
| 8 × 4625 from one IP | 100016, level 11 |
| 5156 | 100020, level 0 |
| 4688 `svchost.exe` → `taskhostw.exe` | 100021, level 0 |

FIM rules (100001, 100002) need real syscheck events: change a monitored file on a test agent, for example `sudo touch /etc/sudoers.d/zz-test && sudo rm /etc/sudoers.d/zz-test`, and look for rule 100001 in the Dashboard.

---

## 3. Single Event by Hand

```bash
sudo /var/ossec/bin/wazuh-logtest < tests/samples/auditd_sudoers.log
```

Or start `wazuh-logtest` interactively and paste a line from `tests/samples/`.

---

## 4. Adding a Test

1. Put the event (one line, anonymised) into `tests/samples/<name>.log`.
2. Add a case to `tests/cases.json`:
   ```json
   {"name": "description", "events": [{"file": "samples/<name>.log"}], "expect": {"rule_id": "1000NN", "level": 12}}
   ```
   `expect` checks the last event, `expect_any` passes if any event matches, `expect_none` fails if any event matches; `"replace": {"old": "new"}` changes an event on the fly.
3. Run `sudo python3 tests/run_logtest.py --skip-tag eventchannel -v` (Windows cases run in CI).

---

## 5. Telegram

`setup.sh` sends a test message at the end. To replay a real alert see `docs/DEPLOYMENT_GUIDE.md`, section 4.
