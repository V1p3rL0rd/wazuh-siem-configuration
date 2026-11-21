# Wazuh SIEM: Baseline Configuration and Telegram Alerting

**English** | [Русский](README.ru.md)

Baseline configuration for a **Wazuh 4.x** manager and its agents: MITRE ATT&CK-mapped detection rules for Ubuntu and Windows servers, noise reduction, queue tuning, index retention and **Telegram notifications for alerts of level 10 and above**. One script configures an installed manager; installers onboard Ubuntu and Windows agents.

Tested with Wazuh 4.14.

---

## Contents

1. [Requirements](#1-requirements)
2. [Manager setup](#2-manager-setup)
3. [Agent deployment](#3-agent-deployment)
4. [Verification](#4-verification)
5. [Rules](#5-rules)
6. [Update and rollback](#6-update-and-rollback)
7. [Repository layout](#7-repository-layout)

---

## 1. Requirements

- Installed Wazuh manager 4.x (all-in-one or manager node), Linux with systemd, `python3`, root access.
- Telegram bot token (from `@BotFather`) and the chat ID of the group or channel (`-100…`), the bot added to it.
- Outbound HTTPS from the manager to `api.telegram.org`.
- Agents: Ubuntu 20.04 / 22.04 / 24.04, Windows Server 2016–2025.

---

## 2. Manager setup

```bash
git clone https://github.com/V1p3rL0rd/wazuh-siem-configuration.git
cd wazuh-siem-configuration
sudo bash setup.sh
```

The script asks only for missing values (manager IP/FQDN, Telegram token and chat ID, optional Indexer password) and stores them in `.env` (`chmod 600`, not committed). The agent version is detected from the manager.

What `setup.sh` does:

1. Checks that `local_rules.xml` / `local_decoder.xml` on the server contain nothing that is not in this repository, and that rule IDs do not clash with other rule files.
2. Backs up every file it changes to `/var/ossec/backup/setup-<date>-XXXX/`.
3. `ossec.conf`: disables raw archives (`logall`), sets `queue_size` for agent connections, adds the Telegram integration (level ≥ 10). Other sections, including syslog receivers, are not changed.
4. `local_internal_options.conf`: analysis queue sizes as a managed block; other lines are kept.
5. Installs the rules, decoders and the Telegram integration script.
6. Validates **before restart**: `wazuh-analysisd -t`, `wazuh-remoted -t` and the test events in `tests/cases.json` through `wazuh-logtest`. On error the backup is restored and the manager is not restarted.
7. Restarts `wazuh-manager` and waits for `analysisd` and `remoted`. If they do not start, the backup is restored.
8. Optional: applies the OpenSearch retention policy (delete indices after 90 days).
9. Sends a test message to Telegram and prints a summary.

If the server already has custom rules or decoders in `local_rules.xml` / `local_decoder.xml`, the script stops and lists them. Move them to separate files (Wazuh loads every file in these directories):

```text
/var/ossec/etc/rules/custom_rules.xml
/var/ossec/etc/decoders/custom_decoders.xml
```

and run `sudo bash setup.sh` again, or replace the files anyway with `sudo bash setup.sh --force-rules` (a backup is kept).

Telegram through a TLS-inspecting proxy: put the proxy CA certificate (PEM) into `/var/ossec/etc/telegram-ca.pem`. Certificate verification is never disabled.

---

## 3. Agent deployment

The agent version must not be newer than the manager (`/var/ossec/bin/wazuh-control info` on the manager).

### Ubuntu

```bash
sudo bash agent-configs/linux/install-ubuntu.sh <MANAGER_IP_OR_FQDN> [AGENT_NAME] <AGENT_VERSION>
# optional group:
sudo WAZUH_AGENT_GROUP=linux-server bash agent-configs/linux/install-ubuntu.sh <MANAGER> "$(hostname)" 4.14.5
```

Installs the agent from the official repository and holds its version (`apt-mark hold`), applies `agent-configs/linux/ossec.conf` (real-time FIM of `/etc`, `/boot`, system binaries; auth, syslog, dpkg, auditd logs; SCA; inventory) and the auditd rules `agent-configs/linux/audit.rules`.

> `audit.rules` ends with `-e 2` (immutable rules): changing audit rules afterwards requires a reboot.

### Windows

Elevated PowerShell:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\agent-configs\windows\install-windows.ps1 -WazuhManager "<MANAGER_IP_OR_FQDN>" -AgentVersion "4.14.5" [-AgentGroup "windows-server"] [-InstallSysmon]
```

Downloads the MSI and (optionally) Sysmon, checks their digital signatures, installs the agent, applies `agent-configs/windows/ossec.conf` (Security / System / PowerShell / Defender / Sysmon channels, FIM, registry run keys) and verifies that the `WazuhSvc` service is running.

### Active Directory domain controllers (optional)

1. On the DC agent use `agent-configs/windows/ossec-dc.conf` instead of `ossec.conf` (replace `<WAZUH_MANAGER_IP>`).
2. On the manager enable the AD rules (DCSync, Kerberoasting, AS-REP roasting, NTLM spraying, SID history):
   ```bash
   sudo cp rules-and-decoders/ad_ds_rules.xml.optional /var/ossec/etc/rules/ad_ds_rules.xml
   sudo chown root:wazuh /var/ossec/etc/rules/ad_ds_rules.xml && sudo chmod 640 /var/ossec/etc/rules/ad_ds_rules.xml
   sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
   ```

---

## 4. Verification

```bash
sudo /var/ossec/bin/wazuh-control status                       # all daemons running
sudo python3 tests/run_logtest.py --skip-tag eventchannel -v   # test events -> expected rules and levels
sudo tail -f /var/ossec/logs/integrations.log                  # Telegram integration errors
```

Manual test of a single event:

```bash
sudo /var/ossec/bin/wazuh-logtest < tests/samples/linux_log_wipe.log    # expected rule 100003, level 12
```

Windows rules are tested in CI (see `docs/TESTING_AND_VERIFICATION.md`); on a manager they apply to events received from agents.

---

## 5. Rules

`rules-and-decoders/local_rules.xml`, IDs 100001–100022. Level ≥ 10 is sent to Telegram.

| ID | Level | Detection | MITRE |
|---|---|---|---|
| 100001 | 12 | FIM: `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `/etc/pam.d/` changed | T1078, T1548.003 |
| 100002 | 9 | FIM: system binary in `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` changed (below Telegram: package upgrades) | T1036, T1574 |
| 100003 | 12 | Linux log destruction (`rm -rf /var/log`, `shred`, `truncate`, `journalctl --vacuum`) | T1070.002 |
| 100004 | 11 | auditd: `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` modified | T1098 |
| 100005 | 13 | auditd: kernel module loaded or removed | T1547.006 |
| 100006 | 14 | Successful SSH logon from an address with multiple failed attempts (10 min) | T1110, T1078 |
| 100010 | 14 | Windows Security / System log cleared (1102, 104) | T1070.001 |
| 100011 | 12 | Account added to Administrators / Domain Admins / Enterprise Admins (4728, 4732, 4756) | T1098 |
| 100012 | 10 | New Windows service (7045, 4697) | T1543.003 |
| 100014 | 12 | Suspicious PowerShell script block (4104) | T1059.001, T1027 |
| 100015 | 11 | LOLBin download / shadow copy deletion (Sysmon event 1) | T1218, T1490 |
| 100016 | 11 | 8 failed Windows logons from one IP in 2 minutes | T1110.001 |
| 100017 | 11 | LOLBin download / shadow copy deletion (4688) | T1218, T1490 |
| 100020 | 0 | Suppress Windows Filtering Platform 5156 / 5158 | — |
| 100021 | 0 | Suppress `svchost.exe` → `taskhostw.exe` / `conhost.exe` (4688) | — |
| 100022 | 0 | Suppress cron session open/close | — |

---

## 6. Update and rollback

Update:

```bash
git pull
sudo bash setup.sh
```

Rollback to the state before a run (the path is printed by `setup.sh`):

```bash
B=/var/ossec/backup/setup-<date>-XXXX
while read -r state path; do
  if [ "$state" = present ]; then sudo cp -a "$B/$(basename "$path")" "$path"; else sudo rm -f "$path"; fi
done < "$B/MANIFEST"
sudo systemctl restart wazuh-manager
```

---

## 7. Repository layout

```text
setup.sh                               manager setup (entry point)
lib/env.sh, lib/ossec_conf.py          .env handling, safe edits of ossec.conf / local_internal_options.conf
server-config/                         ossec.conf reference, internal options, ISM retention policy
rules-and-decoders/                    detection rules, decoders, optional AD rules
integrations/telegram/                 Telegram integration for wazuh-integratord
agent-configs/linux, agent-configs/windows   agent installers and configurations, auditd rules, Sysmon profile
tests/                                 test events, expected results, wazuh-logtest runner, unit tests
docs/                                  deployment, log optimization and testing notes
```

## License

MIT — see [LICENSE.txt](LICENSE.txt).
