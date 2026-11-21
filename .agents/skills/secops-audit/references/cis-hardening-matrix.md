# CIS Hardening, SIEM & Antivirus Exclusion Matrix (SecOps)

This reference outlines security posture requirements across host operating systems, SIEM (Wazuh), and endpoint protection (Kaspersky Security Center).

---

## 1. Host Hardening (CIS Benchmark Baseline)

| Control Area | Requirement | Verification Command |
| :--- | :--- | :--- |
| **SSH Root Login** | Disabled (`PermitRootLogin no`) | `sshd -T \| grep permitrootlogin` |
| **SSH Password Auth** | Disabled (`PasswordAuthentication no`) | `sshd -T \| grep passwordauthentication` |
| **SSH Key Types** | Ed25519 or RSA >= 3072 bit only | Check `/etc/ssh/sshd_config.d/` |
| **Reverse Path Filter** | Enabled (`rp_filter = 1`) | `sysctl net.ipv4.conf.all.rp_filter` |
| **TCP SYN Cookies** | Enabled (`tcp_syncookies = 1`) | `sysctl net.ipv4.tcp_syncookies` |
| **ICMP Redirects** | Disabled (`accept_redirects = 0`) | `sysctl net.ipv4.conf.all.accept_redirects` |
| **SUID/SGID Binaries** | Unnecessary SUID stripped | `find / -perm -4000 -type f` |

---

## 2. Wazuh SIEM Custom Rules Baseline

- **Rule File Location**: `/var/ossec/etc/rules/local_rules.xml`
- **Decoder Location**: `/var/ossec/etc/decoders/local_decoder.xml`
- **Rule ID Allocation**: Use IDs between `100000` and `120000` for user-defined rules.
- **Mandatory Pre-Reload Test**:
  ```bash
  /var/ossec/bin/wazuh-logtest
  ```
  Never reload or restart `wazuh-manager` without a clean `wazuh-logtest` validation.

---

## 3. Kaspersky Security Center (KSC / KES) Exclusions

To avoid catastrophic I/O locks and performance degradation on production infrastructure, configure explicit real-time scan exclusions:

| Server Role | Excluded Directories & File Extensions | Excluded Processes |
| :--- | :--- | :--- |
| **PostgreSQL** | `/var/lib/postgresql/`, `PGDATA`, `*.wal`, `*.bin` | `postgres` |
| **MySQL / MariaDB**| `/var/lib/mysql/`, `*.ibd`, `*.frm`, `ibdata*`, `*.log` | `mysqld` |
| **MS SQL Server** | `*.mdf`, `*.ldf`, `*.ndf`, `*.bak`, `tempdb` paths | `sqlservr.exe` |
| **Proxmox / Hyper-V** | VM disk images (`*.qcow2`, `*.raw`, `*.vhdx`), ZFS pools | `qemu-system-*`, `pve-ha-*` |
| **Veeam / PBS** | Repository stores, immutable chunk directories | `Veeam*`, `proxmox-backup-proxy` |
