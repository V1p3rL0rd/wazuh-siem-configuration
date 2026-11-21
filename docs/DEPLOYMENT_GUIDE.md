# Wazuh SIEM: Deployment and Operations Manual

Step-by-step commands are in the [README](../README.md). This manual covers sizing, pre-checks and troubleshooting.

---

## 1. System Requirements & Host Pre-Checks

### Recommended hardware (all-in-one: indexer, manager, dashboard)
- **CPU:** 4 vCPU minimum (8 vCPU for 50+ agents).
- **RAM:** 8–16 GB (at least 4 GB for the Indexer JVM heap).
- **Storage:** 100+ GB SSD/NVMe.
- **OS:** Ubuntu Server 22.04 / 24.04 LTS or Debian 12.

### Pre-check commands
```bash
# Indexer (OpenSearch) memory map limit: must be >= 262144
sysctl vm.max_map_count
sudo sysctl -w vm.max_map_count=262144
echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-wazuh.conf

# Ports: 443 dashboard, 1514 agents, 1515 enrollment, 9200 indexer, 55000 API
sudo ss -tulpn | grep -E ':(443|1514|1515|9200|55000)\s'

# Time synchronisation (alert ordering and correlation depend on it)
timedatectl | grep -E 'synchronized|NTP'
```

---

## 2. Manager Configuration

```bash
git clone https://github.com/V1p3rL0rd/wazuh-siem-configuration.git
cd wazuh-siem-configuration
sudo bash setup.sh
```

`.env` (repository root, `chmod 600`, not committed) holds `WAZUH_SERVER_IP`, `WAZUH_SERVER_FQDN`, `WAZUH_VERSION`, `TELEGRAM_BOT_TOKEN`, `TELEGRAM_CHAT_ID`, `INDEXER_PASSWORD` (optional). `setup.sh` asks only for missing or placeholder values. For unattended runs create it from `.env.example` beforehand; values must not contain spaces, quotes, `\`, `$` or `#`.

Every run creates `/var/ossec/backup/setup-<date>-XXXX/` with the previous versions of the changed files and a `MANIFEST`. Validation failures and failed restarts restore it automatically.

---

## 3. Agent Onboarding

See the README, section 3. Notes:

- The agent version must not be newer than the manager. The Ubuntu installer holds the package (`apt-mark hold wazuh-agent`); upgrade agents only after the manager.
- `WAZUH_AGENT_GROUP` (Ubuntu) / `-AgentGroup` (Windows) must name an existing group on the manager, otherwise enrollment is rejected (`wazuh-authd: Invalid group`).
- Process creation rules: rule 100015 needs Sysmon (`-InstallSysmon`), rule 100017 needs Security event 4688 collection and the "Audit Process Creation" policy with command line logging.

---

## 4. Verification and Troubleshooting

### Daemon status
```bash
/var/ossec/bin/wazuh-control status
```
`wazuh-analysisd`, `wazuh-remoted`, `wazuh-integratord`, `wazuh-modulesd`, `wazuh-db`, `wazuh-apid` must be running.

### Rules
```bash
sudo /var/ossec/bin/wazuh-analysisd -t       # configuration and rules syntax
sudo python3 tests/run_logtest.py --skip-tag eventchannel -v   # test events -> expected rules
```

### Telegram delivery
- Integration errors: `sudo tail -f /var/ossec/logs/integrations.log` and `sudo grep integratord /var/ossec/logs/ossec.log`.
- Replay an alert: save one line of `/var/ossec/logs/alerts/alerts.json` to a file and run
  ```bash
  sudo /var/ossec/integrations/custom-telegram /tmp/alert.json "<CHAT_ID>" "<BOT_TOKEN>"
  ```
- `CERTIFICATE_VERIFY_FAILED`: a TLS-inspecting proxy is in the path; put its CA (PEM) into `/var/ossec/etc/telegram-ca.pem`.
- Identical alerts (same rule, agent and source/target) within 15 seconds are sent once (`suppressed by flood control` in the integration log).
