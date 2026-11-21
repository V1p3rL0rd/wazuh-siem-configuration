# Log Collection, Noise Reduction and Alert Levels

The goal is high-signal alerts with low event volume: agents collect selected events, the manager drops benign noise at level 0, and only level 10+ alerts reach Telegram.

---

## 1. Processing Flow

```
[ Log sources ]
      │
      ▼
[ Wazuh agent ] ── collects only selected Windows events (XPath queries), auditd keys, FIM paths
      │  (AES-encrypted agent protocol, TCP 1514)
      ▼
[ Wazuh manager ] ── decoders → rules (local_rules.xml) → level 0 = not stored as alert
      │
      ├──► Indexer / Dashboard (alerts)
      └──► Telegram (alerts level >= 10, custom-telegram integration)
```

`<logall>` / `<logall_json>` are disabled: raw events that did not produce an alert are not archived.

---

## 2. Windows Agents (`agent-configs/windows/ossec.conf`)

| Channel | Events |
|---|---|
| Security | 1102 (log cleared), 4624 / 4625 (logon success / failure), 4672 (special privileges), 4697 / 7045 (service installed), 4698 (scheduled task), 4720 / 4726 / 4738 (account created / deleted / changed), 4728 / 4732 (added to privileged group) |
| System | 104 (log cleared), 1074, 6005 / 6006 (restart, event log start/stop), 7034 / 7036 (service crash / state), 7045 |
| PowerShell/Operational | 4104 (script block logging) |
| Windows Defender/Operational | 1116 / 1117 (malware detected / action), 5001 (real-time protection disabled) |
| Sysmon/Operational | all events of the Sysmon profile `sysmonconfig.xml` |

Domain controllers (`ossec-dc.conf`) additionally collect the Kerberos, NTLM, directory replication and directory change events used by `ad_ds_rules.xml.optional`.

Process creation (4688) is not collected by default because of its volume; use Sysmon (rule 100015) or add 4688 to the Security query (rules 100017, 100021).

---

## 3. Ubuntu Agents

1. **auditd** (`audit.rules`, CIS-aligned, 64- and 32-bit syscalls): identity files (`passwd_change`, `identity_changes`), sudoers (`sudoers_change`), kernel modules (`kernel_modules`), time changes, hostname / network configuration, permission changes by users, `sudo` / `su`, `nc` / `ncat` / `socat`.
2. **FIM** (`ossec.conf`): real-time monitoring of `/etc`, `/boot`, `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin`, `/usr/local/{bin,sbin}`; `<nodiff>` for `/etc/shadow` and `/etc/gshadow`, so password hashes never appear in alerts.
3. **Logs**: `auth.log`, `syslog`, `dpkg.log`, `audit.log`.

---

## 4. Manager-Side Noise Reduction

| Rule | Drops |
|---|---|
| 100020 | Windows Filtering Platform permit events 5156 / 5158 |
| 100021 | 4688 `svchost.exe` → `taskhostw.exe` / `conhost.exe` |
| 100022 | cron PAM session open / close |

A Windows event first walks the built-in rule chain (60000 → channel → event rule). Therefore:

- detection rules use `<if_group>windows</if_group>`, which makes them children of every rule in that chain;
- level-0 suppression rules are children of the exact rule the event ends on (5156 → 60103, 4688 → 67027), otherwise the built-in rule wins.

Both are covered by the CI tests.

---

## 5. Alert Levels

| Level | Meaning | Destination |
|:---:|---|---|
| 0 | Suppressed noise | not stored |
| 1–9 | Informational and low-severity events (e.g. rule 100002: system binary changed, usually by package upgrades) | Indexer / Dashboard |
| 10–12 | Suspicious activity: brute force, privileged group or sudoers changes, malicious PowerShell, LOLBins, new services | Indexer + Telegram |
| 13–15 | High impact: log cleared, kernel module loaded, successful logon after brute force | Indexer + Telegram |
