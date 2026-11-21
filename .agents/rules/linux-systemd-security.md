---
trigger: model_decision
description: "Rules and best practices for Linux OS administration, systemd service sandboxing, kernel sysctl tuning, and CIS host-level security hardening."
---

# Linux Administration, systemd Sandboxing & Host Security

This rule is activated when modifying systemd unit files, configuring Linux host operating systems, tuning kernel parameters, or implementing host security policies.

---

## 1. systemd Service Unit Hardening

All newly created or managed systemd services must follow defense-in-depth isolation principles. Avoid running custom daemons as root whenever possible.

### Mandatory Sandboxing Directives

When writing `[Service]` sections, incorporate the following security baseline:

```ini
[Unit]
Description=Example Production Daemon
After=network-online.target
Wants=network-online.target

[Service]
Type=exec
User=appuser
Group=appgroup

# Process Lifecycle
Restart=on-failure
RestartSec=5s
TimeoutStopSec=30s
LimitNOFILE=65536
LimitNPROC=4096

# Sandboxing & Filesystem Protection
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
PrivateTmp=true
PrivateDevices=true
NoNewPrivileges=true

# Capabilities & Memory
CapabilityBoundingSet=
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true

# Writable Paths (explicit white-listing)
ReadWritePaths=/var/log/app /var/run/app

[Install]
WantedBy=multi-user.target
```

---

## 2. Kernel & Networking Sysctl Baseline

Kernel parameters must be configured via drop-in files under `/etc/sysctl.d/99-infra-baseline.conf`:

### Network Stack & Anti-Spoofing
- **Reverse Path Filtering**: Enable strict reverse path filtering on all interfaces:
  ```ini
  net.ipv4.conf.all.rp_filter = 1
  net.ipv4.conf.default.rp_filter = 1
  ```
- **Disable ICMP Redirects & Source Routing**:
  ```ini
  net.ipv4.conf.all.accept_redirects = 0
  net.ipv4.conf.all.send_redirects = 0
  net.ipv4.conf.all.accept_source_route = 0
  net.ipv6.conf.all.accept_redirects = 0
  net.ipv6.conf.all.accept_source_route = 0
  ```
- **SYN Flood Protection**:
  ```ini
  net.ipv4.tcp_syncookies = 1
  net.ipv4.tcp_max_syn_backlog = 8192
  ```

### Virtual Memory & Resource Limits
- Avoid aggressive swapping on high-throughput servers: `vm.swappiness = 10`.
- Protect against kernel panic on out-of-memory: `vm.panic_on_oom = 0`.
- Enable memory overcommit safeguards as appropriate for application workload.

---

## 3. Host-Level Security & Access Management (CIS Baseline)

### A. SSH Hardening (`/etc/ssh/sshd_config.d/hardening.conf`)
- Disallow root login over SSH: `PermitRootLogin no`.
- Disallow password authentication: `PasswordAuthentication no`.
- Enforce modern cryptographic key exchange and host keys:
  - Allowed host keys: `ssh-ed25519`, `rsa-sha2-512`.
  - Disallow legacy DSA and SHA-1 keys.
- Set idle timeout: `ClientAliveInterval 300` and `ClientAliveCountMax 2`.

### B. Filesystem Mount Hardening (`/etc/fstab`)
- Add restrictive flags to shared and temporary filesystems:
  - `/tmp`: `nodev,nosuid,noexec`
  - `/dev/shm`: `nodev,nosuid,noexec`
  - `/var/tmp`: `nodev,nosuid`

### C. Audit Logging (`auditd`)
- Enable `auditd` rules monitoring system calls for file permission changes, unauthorized access attempts, and execution of privileged binaries (`sudo`, `su`, `/etc/shadow`, `/etc/pam.d/`).
