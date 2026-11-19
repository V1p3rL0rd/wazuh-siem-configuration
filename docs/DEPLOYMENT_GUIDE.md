# Wazuh SIEM: Deployment and Operations Manual

This guide documents the enterprise deployment of **Wazuh SIEM v4.x** (Indexer, Manager, Dashboard), Telegram alerting integration, and host-level onboarding for Ubuntu Server and Windows Server nodes.

---

## 1. System Requirements & Host Pre-Checks

### Recommended Hardware Allocations:
- **CPU:** 4 vCPU minimum (8 vCPU recommended for 50+ monitored agents).
- **RAM:** 8–16 GB RAM (minimum 4 GB dedicated to OpenSearch / Indexer JVM heap).
- **Storage:** 100+ GB NVMe / SSD (high IOPS required for OpenSearch indexing).
- **Operating System:** Ubuntu Server 22.04 / 24.04 LTS or Debian 12.

### Host Pre-Check Commands:
```bash
# 1. Verify kernel memory mapping limit for OpenSearch / Indexer
sysctl vm.max_map_count
# Must be >= 262144. If lower, apply immediately:
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.d/99-wazuh.conf

# 2. Check required port bindings
sudo ss -tulpn | grep -E ':(443|1514|1515|9200|55000)\s'

# 3. Verify Docker runtime and compose plugin (if using containerized stack)
docker --version && docker compose version
```

---

## 2. Server Deployment & Hardening

### Step 2.1: Turnkey Automated Deployment (`setup.sh`)
For both bare-metal/VM Wazuh installations and containerized setups, run the master installer from the repository root:
```bash
cd wazuh-siem
sudo bash setup.sh
```

**Automated operations executed by `setup.sh`:**
1. Securely prompts for Telegram Bot credentials (if not already set in `.env`).
2. Locks `.env` permissions strictly to `root:root (600)`.
3. Creates timestamped configuration backups (`ossec.conf.bak_<timestamp>`).
4. Cleans up stale crash lockfiles (`/var/ossec/var/run/.restart`) to prevent API Error 1017 stalls.
5. Injects the Telegram integration into the primary `<ossec_config>` section and tunes daemon queue sizes using safe Python-based XML processing.
6. Deploys custom detection rules and validates syntax via `/var/ossec/bin/wazuh-analysisd -t` with automated rollback on failure.
7. Gracefully restarts `wazuh-manager` and `wazuh-dashboard`, monitoring API status until all daemons are verified healthy.
8. Dispatches an end-to-end verification alert directly to Telegram.

### Step 2.2: Environment Configuration (.env)
Copy `.env.example` to `.env` and configure your credentials:
```bash
cp .env.example .env
chmod 600 .env
nano .env
```

Required variables for Wazuh SIEM:
```ini
TELEGRAM_BOT_TOKEN="123456789:ABCDefGhIJKlmNoPQRsTUVwxyZ"
TELEGRAM_CHAT_ID="-1001234567890"
INDEXER_PASSWORD="<REDACTED_INDEXER_PASSWORD>"
WAZUH_SERVER_IP="10.100.68.68"
WAZUH_SERVER_FQDN="wazuh.garuda.net"
```

---

## 3. Monitored Agent Onboarding

### 3.1 Ubuntu Server (Linux)
Run on target Ubuntu 20.04 / 22.04 / 24.04 LTS servers:
```bash
sudo bash agent-configs/linux/install-ubuntu.sh wazuh.garuda.net
```
* **Capabilities enabled:**
  * Automated installation from the official Wazuh repository.
  * Deployment of CIS benchmark `auditd` rules (`/etc/audit/rules.d/99-wazuh-secops.rules`).
  * Real-time File Integrity Monitoring (FIM) for `/etc`, `/bin`, `/sbin`, and `/boot`.
  * Automatic suppression of repetitive cron session open/close noise.

### 3.2 Windows Server (2016 / 2019 / 2022 / 2025)
Run in an elevated Administrator PowerShell session:
```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\agent-configs\windows\install-windows.ps1 -WazuhManager "wazuh.garuda.net" -InstallSysmon
```
* **Capabilities enabled:**
  * Silent unattended MSI deployment with automated manager registration.
  * Sysmon v15+ deployment with optimized configuration profile.
  * XPath-targeted queries on `Security`, `System`, and `PowerShell/Operational` channels.
  * Suppression of high-volume Windows Filtering Platform (WFP 5156/5158) traffic.

---

## 4. Verification and Troubleshooting

### Checking Core Daemon Status:
```bash
/var/ossec/bin/wazuh-control status
```
Expected output:
* `wazuh-analysisd is running...`
* `wazuh-remoted is running...`
* `wazuh-syscheckd is running...`
* `wazuh-logcollector is running...`
* `wazuh-integratord is running...`
* `wazuh-modulesd is running...`
* `wazuh-db is running...`
* `wazuh-apid is running...`

### Troubleshooting Integrations & Telegram Delivery:
* **Daemon Logs:** `tail -f /var/ossec/logs/ossec.log | grep integratord`
* **Integration Script Output:** `tail -f /var/ossec/logs/integrations.log`
* **Manual Replay of Latest Alert:**
  ```bash
  /var/ossec/integrations/custom-telegram /tmp/real_alert_2502.json
  ```
