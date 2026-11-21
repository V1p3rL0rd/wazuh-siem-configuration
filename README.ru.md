# Wazuh SIEM: базовая конфигурация и оповещения в Telegram

[English](README.md) | **Русский**

Базовая конфигурация менеджера **Wazuh 4.x** и его агентов: правила обнаружения с привязкой к MITRE ATT&CK для серверов Ubuntu и Windows, подавление шума, настройка очередей, срок хранения индексов и **оповещения в Telegram для алертов уровня 10 и выше**. Один скрипт настраивает установленный менеджер, установщики подключают агентов Ubuntu и Windows.

Проверено на Wazuh 4.14.

---

## Содержание

1. [Требования](#1-требования)
2. [Настройка менеджера](#2-настройка-менеджера)
3. [Установка агентов](#3-установка-агентов)
4. [Проверка](#4-проверка)
5. [Правила](#5-правила)
6. [Обновление и откат](#6-обновление-и-откат)
7. [Структура репозитория](#7-структура-репозитория)

---

## 1. Требования

- Установленный менеджер Wazuh 4.x (all-in-one или узел менеджера), Linux с systemd, `python3`, права root.
- Токен Telegram-бота (от `@BotFather`) и ID группы или канала (`-100…`), бот добавлен в чат.
- Исходящий HTTPS от менеджера к `api.telegram.org`.
- Агенты: Ubuntu 20.04 / 22.04 / 24.04, Windows Server 2016–2025.

---

## 2. Настройка менеджера

```bash
git clone https://github.com/V1p3rL0rd/wazuh-siem-configuration.git
cd wazuh-siem-configuration
sudo bash setup.sh
```

Скрипт спрашивает только недостающие значения (IP/FQDN менеджера, токен и ID чата Telegram, необязательный пароль Indexer) и сохраняет их в `.env` (`chmod 600`, не коммитится). Версия агентов определяется по менеджеру.

Что делает `setup.sh`:

1. Проверяет, что в `local_rules.xml` / `local_decoder.xml` на сервере нет ничего, чего нет в репозитории, и что ID правил не пересекаются с другими файлами правил.
2. Сохраняет каждый изменяемый файл в `/var/ossec/backup/setup-<дата>-XXXX/`.
3. `ossec.conf`: отключает архив сырых событий (`logall`), задаёт `queue_size` для подключений агентов, добавляет интеграцию с Telegram (уровень ≥ 10). Остальные секции, включая приём Syslog, не меняются.
4. `local_internal_options.conf`: размеры очередей анализа отдельным управляемым блоком, остальные строки сохраняются.
5. Устанавливает правила, декодеры и скрипт интеграции с Telegram.
6. Проверяет **до перезапуска**: `wazuh-analysisd -t`, `wazuh-remoted -t` и тестовые события из `tests/cases.json` через `wazuh-logtest`. При ошибке восстанавливает резервную копию, менеджер не перезапускается.
7. Перезапускает `wazuh-manager` и ждёт запуска `analysisd` и `remoted`. Если они не запустились, восстанавливает резервную копию.
8. Необязательно: применяет политику хранения OpenSearch (удаление индексов старше 90 дней).
9. Отправляет тестовое сообщение в Telegram и выводит итог.

Если на сервере уже есть свои правила или декодеры в `local_rules.xml` / `local_decoder.xml`, скрипт остановится и покажет их список. Перенесите их в отдельные файлы (Wazuh загружает все файлы этих каталогов):

```text
/var/ossec/etc/rules/custom_rules.xml
/var/ossec/etc/decoders/custom_decoders.xml
```

и запустите `sudo bash setup.sh` снова, либо замените файлы принудительно: `sudo bash setup.sh --force-rules` (резервная копия сохраняется).

Telegram через прокси с подменой TLS-сертификатов: положите сертификат CA прокси (PEM) в `/var/ossec/etc/telegram-ca.pem`. Проверка сертификата не отключается.

---

## 3. Установка агентов

Версия агента не должна быть новее менеджера (`/var/ossec/bin/wazuh-control info` на менеджере).

### Ubuntu

```bash
sudo bash agent-configs/linux/install-ubuntu.sh <IP_ИЛИ_FQDN_МЕНЕДЖЕРА> [ИМЯ_АГЕНТА] <ВЕРСИЯ_АГЕНТА>
# с группой:
sudo WAZUH_AGENT_GROUP=linux-server bash agent-configs/linux/install-ubuntu.sh <МЕНЕДЖЕР> "$(hostname)" 4.14.5
```

Устанавливает агента из официального репозитория и фиксирует его версию (`apt-mark hold`), применяет `agent-configs/linux/ossec.conf` (FIM в реальном времени для `/etc`, `/boot`, системных бинарников; журналы auth, syslog, dpkg, auditd; SCA; инвентаризация) и правила auditd `agent-configs/linux/audit.rules`.

> `audit.rules` заканчивается `-e 2` (неизменяемые правила): после этого правила auditd меняются только с перезагрузкой.

### Windows

PowerShell от имени администратора:

```powershell
Set-ExecutionPolicy Bypass -Scope Process -Force
.\agent-configs\windows\install-windows.ps1 -WazuhManager "<IP_ИЛИ_FQDN_МЕНЕДЖЕРА>" -AgentVersion "4.14.5" [-AgentGroup "windows-server"] [-InstallSysmon]
```

Скачивает MSI и (по желанию) Sysmon, проверяет их цифровые подписи, устанавливает агента, применяет `agent-configs/windows/ossec.conf` (каналы Security / System / PowerShell / Defender / Sysmon, FIM, ключи автозапуска в реестре) и проверяет, что служба `WazuhSvc` запущена.

### Контроллеры домена Active Directory (по желанию)

1. На агенте контроллера домена используйте `agent-configs/windows/ossec-dc.conf` вместо `ossec.conf` (замените `<WAZUH_MANAGER_IP>`).
2. На менеджере включите правила AD (DCSync, Kerberoasting, AS-REP roasting, NTLM spraying, SID history):
   ```bash
   sudo cp rules-and-decoders/ad_ds_rules.xml.optional /var/ossec/etc/rules/ad_ds_rules.xml
   sudo chown root:wazuh /var/ossec/etc/rules/ad_ds_rules.xml && sudo chmod 640 /var/ossec/etc/rules/ad_ds_rules.xml
   sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
   ```

---

## 4. Проверка

```bash
sudo /var/ossec/bin/wazuh-control status                       # все демоны запущены
sudo python3 tests/run_logtest.py --skip-tag eventchannel -v   # тестовые события -> ожидаемые правила и уровни
sudo tail -f /var/ossec/logs/integrations.log                  # ошибки интеграции с Telegram
```

Ручная проверка одного события:

```bash
sudo /var/ossec/bin/wazuh-logtest < tests/samples/linux_log_wipe.log    # ожидается правило 100003, уровень 12
```

Windows-правила проверяются в CI (см. `docs/TESTING_AND_VERIFICATION.md`), на менеджере они применяются к событиям от агентов.

---

## 5. Правила

`rules-and-decoders/local_rules.xml`, ID 100001–100022. Уровень ≥ 10 уходит в Telegram.

| ID | Уровень | Что обнаруживает | MITRE |
|---|---|---|---|
| 100001 | 12 | FIM: изменены `/etc/shadow`, `/etc/gshadow`, `/etc/sudoers*`, `/etc/pam.d/` | T1078, T1548.003 |
| 100002 | 9 | FIM: изменён системный бинарник в `/bin`, `/sbin`, `/usr/bin`, `/usr/sbin` (ниже порога Telegram: обновления пакетов) | T1036, T1574 |
| 100003 | 12 | Уничтожение журналов Linux (`rm -rf /var/log`, `shred`, `truncate`, `journalctl --vacuum`) | T1070.002 |
| 100004 | 11 | auditd: изменены `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | T1098 |
| 100005 | 13 | auditd: загрузка или выгрузка модуля ядра | T1547.006 |
| 100006 | 14 | Успешный вход по SSH с адреса, с которого было несколько неудачных попыток (10 мин) | T1110, T1078 |
| 100010 | 14 | Очищен журнал Windows Security / System (1102, 104) | T1070.001 |
| 100011 | 12 | Учётная запись добавлена в Administrators / Domain Admins / Enterprise Admins (4728, 4732, 4756) | T1098 |
| 100012 | 10 | Новая служба Windows (7045, 4697) | T1543.003 |
| 100014 | 12 | Подозрительный блок скрипта PowerShell (4104) | T1059.001, T1027 |
| 100015 | 11 | LOLBin: загрузка файла / удаление теневых копий (Sysmon, событие 1) | T1218, T1490 |
| 100016 | 11 | 8 неудачных входов в Windows с одного IP за 2 минуты | T1110.001 |
| 100017 | 11 | LOLBin: загрузка файла / удаление теневых копий (4688) | T1218, T1490 |
| 100020 | 0 | Подавление Windows Filtering Platform 5156 / 5158 | — |
| 100021 | 0 | Подавление `svchost.exe` → `taskhostw.exe` / `conhost.exe` (4688) | — |
| 100022 | 0 | Подавление открытия/закрытия сессий cron | — |

---

## 6. Обновление и откат

Обновление:

```bash
git pull
sudo bash setup.sh
```

Откат к состоянию до запуска (путь выводит `setup.sh`):

```bash
B=/var/ossec/backup/setup-<дата>-XXXX
while read -r state path; do
  if [ "$state" = present ]; then sudo cp -a "$B/$(basename "$path")" "$path"; else sudo rm -f "$path"; fi
done < "$B/MANIFEST"
sudo systemctl restart wazuh-manager
```

---

## 7. Структура репозитория

```text
setup.sh                               настройка менеджера (точка входа)
lib/env.sh, lib/ossec_conf.py          работа с .env, безопасная правка ossec.conf / local_internal_options.conf
server-config/                         справочный ossec.conf, внутренние опции, политика хранения ISM
rules-and-decoders/                    правила, декодеры, необязательные правила AD
integrations/telegram/                 интеграция с Telegram для wazuh-integratord
agent-configs/linux, agent-configs/windows   установщики и конфигурации агентов, правила auditd, профиль Sysmon
tests/                                 тестовые события, ожидаемые результаты, запуск wazuh-logtest, unit-тесты
docs/                                  заметки по развёртыванию, оптимизации журналов и тестированию
```

## Лицензия

MIT — см. [LICENSE.txt](LICENSE.txt).
