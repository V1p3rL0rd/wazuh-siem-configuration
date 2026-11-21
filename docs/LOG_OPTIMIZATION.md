# Log Normalization, Optimization & Noise Reduction in Wazuh SIEM

An enterprise SIEM deployment must balance high threat visibility with minimal storage overhead and event noise (Events Per Second - EPS). Unfiltered log ingestion causes disk I/O exhaustion, search latency degradation in OpenSearch / Indexer, and alert fatigue among SecOps engineers.

---

## 1. End-to-End Processing Architecture

```
[ Log Sources ]
       │
       ▼
[ Wazuh Agent (Client-side filtering) ] ────► Drops benign noise BEFORE transmission (XPath / auditd)
       │
       ▼ (Encrypted TLS channel, TCP 1514)
[ Wazuh Manager ] ──────────────────────────► Decoding (local_decoder.xml)
       │                                     Field normalization (Wazuh ECS-aligned schema)
       ▼                                     Rule evaluation & correlation (local_rules.xml)
[ OpenSearch / Indexer ] ◄─────────────────── Event indexing & enrichment (GeoIP, MITRE ATT&CK)
       │
       ▼ (Critical security alerts only: Level >= 10)
[ Telegram Alerting ] ──────────────────────► Real-time notifications to on-call SecOps engineers
```

---

## 2. Windows Server Baseline Monitoring

Rather than collecting raw event floods, our Windows agents capture high-signal security events:

### High-Signal `Security` Channel Events:
* **Authentication:** `4624` (Successful Logon), `4625` (Failed Logon — brute-force detection), `4672` (Special privileges assigned / Administrator logon).
* **Identity & Account Management:** `4720` (User created), `4726` (User deleted), `4728` / `4732` (User added to Administrators or privileged group), `4738` (User account modified).
* **Defense Evasion:** `1102` (Security audit log cleared — Level 14 Critical Telegram alert).
* **Persistence & Execution:** `7045`, `4697` (New Windows service installed), `4698` (Scheduled task created).

### High-Signal `System` Channel Events:
* **System Log Cleared:** `104` (System audit log cleared).
* **Host State Changes:** `1074` (Host reboot/shutdown initiated), `6005` / `6006` (EventLog service started/stopped).
* **Service Failures:** `7034`, `7036` (Critical service crash or termination).

### High-Signal `PowerShell/Operational` Channel Events:
* **Event ID 4104 (ScriptBlock Logging):** Detects execution of `DownloadString`, `-EncodedCommand`, `Invoke-Expression` (`IEX`), and `-ExecutionPolicy Bypass`.

### Noise Suppression:
* Drops Windows Filtering Platform permit packets (`5156`, `5158`) and background `svchost.exe` process churn (`4688`) at rule level 0.

---

## 3. Ubuntu Server (Linux) Optimization

### Challenges:
* Unfiltered `syslog` and `auth.log` are saturated with frequent `cron` sessions (`pam_unix(cron:session): session opened/closed`).
* Lack of command-line detail for privileged shell operations without the Linux Audit subsystem.

### Solution:
1. **Linux Audit Subsystem (`auditd`):**
   * Configured with strict CIS Benchmark audit rules:
     * Authentication and identity files: `/etc/passwd`, `/etc/shadow`, `/etc/group`.
     * Privilege escalation paths: `/etc/sudoers`, `/etc/sudoers.d/`.
     * Kernel module operations: `init_module`, `finit_module`, `delete_module`.
     * Suspicious network tunneling tools: `nc`, `ncat`, `socat`.
2. **File Integrity Monitoring (FIM / `syscheck`):**
   * Critical binaries and configs (`/etc`, `/boot`, `/bin`, `/sbin`) are monitored with `realtime="yes"`.
   * Sensitive credential stores (`/etc/shadow`, `/etc/gshadow`) enforce `<nodiff>` to prevent password hashes from leaking into alert logs.
   * Virtual and temporary file trees (`/proc`, `/sys`, `/dev`, `/tmp`, `*.log`) are explicitly excluded.
3. **Manager-Side Noise Suppression (`local_rules.xml`):**
   * Rule ID `100022` (Level 0) silently discards recurring cron session open/close messages.

---

## 4. Severity Gradation & Rule Hierarchy

| Rule Level | Severity | Description | Action / Route |
|:---:|:---:|:---|:---|
| **0–3** | `NOISE` | Suppressed debug logs, cron sessions, harmless background events | Discarded (Level 0) or indexed for diagnostics |
| **4–7** | `INFO` | Routine operational events (successful user logons, standard service restarts) | Indexed in OpenSearch / Dashboard |
| **8–9** | `LOW` | Minor anomalies (single failed logon, port probe) | Indexed in OpenSearch / Dashboard |
| **10–12** | `HIGH` | Verified suspicious activity: multi-attempt brute force, `/etc/sudoers` modified, user added to Administrators, obfuscated PowerShell | **Forwarded to Telegram & Indexed** |
| **13–15** | `CRITICAL` | Confirmed high-impact attack: Security log cleared (1102/104), successful logon after brute force, LSASS process memory access, core binary replacement | **Immediate High-Priority Telegram Alert** |

> **Design Principle:** Only alerts with **Level $\ge$ 10** trigger external Telegram notifications, ensuring zero alert fatigue and actionable notifications for the SecOps team.
