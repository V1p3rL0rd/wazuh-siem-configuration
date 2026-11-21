---
name: incident-triage
description: Guides structured read-only root-cause triage for Linux servers, network connectivity, DNS, TLS, and service outages using USE and OSI methodologies. Use when troubleshooting high latency, packet loss, service crashes, OOM kills, disk exhaustion, or degraded production hosts. Do not use for routine IaC refactoring or feature planning.
---

# Structured Incident Triage (Read-Only)

## Дерево решений (выбери ветку по симптому)
- **Сеть / недоступность / таймауты** -> Иди по OSI снизу вверх: линк и ошибки интерфейса (`ip -s link`, `ethtool -S`), маршруты/ARP (`ip r get`, `ip neigh`), firewall/conntrack (`nft list ruleset`, `conntrack -S`), сокеты и ретрансмиты (`ss -tinp`, `nstat -az TcpRetransSegs`), DNS/TLS (`dig +trace`, `openssl s_client`).
- **Деградация сервера / CPU / RAM / IO** -> Метод USE (Utilization, Saturation, Errors): `uptime`, `vmstat 1 5`, `mpstat -P ALL 1 3`, `iostat -xz 1 3`, `free -h`, `dmesg -T | grep -iE 'oom|error|reset|link'`, `df -h` и `df -i`.
- **Падение сервиса** -> `systemctl status <svc> --no-pager`, `journalctl -u <svc> -n 150 --no-pager`, проверка лимитов (`cat /proc/<pid>/limits`, `ulimit -a`) и открытых дескрипторов.

## Протокол работы
1. Сформулируй 2–3 приоритетные гипотезы по текущим симптомам.
2. Предложи минимальный пакет **read-only** диагностических команд (одним копируемым блоком) для подтверждения или отсечения гипотез.
3. После получения вывода зафиксируй:
   - **Подтверждённые факты** (со ссылками на строки логов/метрик).
   - **Наиболее вероятную первопричину (Root Cause)**.
   - **Митигацию** (быстрое восстановление сервиса с минимальным риском) и **постоянный фикс**.
4. По завершении инцидента предложи сохранить новый паттерн диагностики через `/learn`.

## Safety
- На этапе триажа запрещены любые рестарты, чистка логов/кэшей, перезапись конфигов и снятие тяжелых дампов (`tcpdump` без `-c` и фильтра, `strace` на высоконагруженный продакшен-процесс без предупреждения о паузе).
