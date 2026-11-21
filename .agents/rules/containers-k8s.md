---
trigger: glob
globs: "**/Dockerfile*, **/*compose*.yml, **/*compose*.yaml, **/k8s/**/*.yaml, **/helm/**, **/manifests/**/*.yaml"
description: "Стандарты безопасности и надёжности для Docker, Docker Compose и Kubernetes."
---

# Стандарты Docker и Kubernetes

## Docker и Compose
- Фиксируй теги образов (избегай `:latest` в prod; для критичных сервисов указывай digest).
- Всегда настраивай `restart: unless-stopped`, ротацию логов (`json-file` с `max-size` и `max-file`) и `healthcheck`.
- Запрещено монтировать `/var/run/docker.sock` в прикладные контейнеры или выдавать `privileged: true` без жёсткого обоснования.

## Kubernetes
- Каждый Deployment/StatefulSet обязан иметь `requests` и `limits` (CPU/Memory), `livenessProbe`/`readinessProbe`, `PodDisruptionBudget` (для HA-сервисов) и `securityContext` (`runAsNonRoot: true`, `allowPrivilegeEscalation: false`).
- Перед применением манифестов всегда выполняй `kubectl diff -f` и `kubectl apply --dry-run=server`.
- Сетевые политики (`NetworkPolicy`) и RBAC строй по принципу минимальных привилегий.
