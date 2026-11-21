---
name: secops-audit
description: >-
  Audits security posture across Linux OS hardening, CIS benchmarks, exposed network ports,
  Wazuh SIEM rule validations, and antivirus (Kaspersky KSC) exclusions.
  Trigger via /secops-audit or during security reviews and compliance gates.
---

# Security Posture & Compliance Audit Runbook (SecOps)

This skill provides an automated and procedural security audit framework. It enforces CIS host hardening, validates SIEM rules before deployment, and verifies that critical production infrastructure is protected without causing I/O lockups.

---

## Audit Workflow

### Step 1: Run Workspace Security Scan
Execute the security hygiene scanner:
```bash
bash .agents/skills/secops-audit/scripts/quick_sec_scan.sh
```

### Step 2: Host & Container Security Audit
Verify against [cis-hardening-matrix.md](./references/cis-hardening-matrix.md):
- [ ] **SSH Hardening**: `PermitRootLogin no`, `PasswordAuthentication no`.
- [ ] **Kernel Sysctl**: Anti-spoofing (`rp_filter = 1`), SYN flood mitigation (`tcp_syncookies = 1`).
- [ ] **Container Isolation**: No unconstrained `privileged: true`, no mounting `/var/run/docker.sock`.
- [ ] **Sensitive Ports**: Verify that management interfaces (iLO, iDRAC, IPMI, Winbox, SSH) are restricted to OOB/Management VLANs.

### Step 3: Wazuh SIEM Rule Testing
Before applying custom rules or decoders to `local_rules.xml`:
```bash
/var/ossec/bin/wazuh-logtest
```
Confirm that rule IDs are strictly within `100000`–`120000` and no existing decoders are broken.

### Step 4: KSC Antivirus Exclusion Review
For any new database node (PG, MySQL, MS SQL) or hypervisor (Proxmox, VMware), verify that data directories, transaction logs, and VM image pools are excluded from real-time file scanning.
