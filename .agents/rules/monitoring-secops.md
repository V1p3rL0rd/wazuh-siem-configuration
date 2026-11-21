---
trigger: model_decision
description: "Применять при настройке мониторинга и ИБ: Zabbix, GAP-stack (Grafana, Alertmanager, Prometheus), ELK-stack, Wazuh SIEM, Kaspersky Security Center (KSC)."
---

# Мониторинг и информационная безопасность

## Мониторинг (Zabbix, GAP-stack, ELK)
- **Zabbix:** избегай дублирования тяжёлых polling-запросов (используй master item + dependent items и preprocessing). Для триггеров обязательно задавай гистерезис (Recovery expression) и зависимости (dependencies), чтобы падение шлюза не вызывало шторм алертов.
- **GAP-stack:** перед перезагрузкой проверяй конфиги через `promtool check config`, `promtool check rules` и `amtool check-config`. Следи за кардинальностью лейблов в Prometheus (запрещено класть IP клиентов, user_id или полные URL в labels).
- **ELK-stack:** для любых новых индексов сразу определяй ILM-политику (retention, rollover по размеру/возрасту) и шаблоны маппинга, чтобы избежать mapping explosion и заполнения диска.

## ИБ-инструменты (Wazuh SIEM, Kaspersky Security Center)
- **Wazuh SIEM:** кастомные правила и декодеры храни только в `local_rules.xml` / `local_decoder.xml` (ID диапазона `100000`–`120000`) и обязательно прогоняй через `wazuh-logtest` до перезапуска `wazuh-manager`.
- **Kaspersky Security Center (KSC):** любые изменения политик, сетевого экрана KES или задач обновления сначала обкатывай на пилотной группе администрирования. При развёртывании KES на серверах СУБД и гипервизорах обязательно настраивай исключения проверки по путям/процессам (файлы БД `.mdf`/`.ldf`/`.ibd`/PGDATA, образы ВМ, каталоги бэкапов Veeam/PBS), чтобы исключить блокировки и деградацию IO.
