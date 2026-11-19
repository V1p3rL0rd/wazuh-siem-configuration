#!/usr/bin/env bash
# ==============================================================================
# collect_diag.sh - Linux Host & Infrastructure Diagnostic Collection
# ==============================================================================
set -euo pipefail

TIMESTAMP=$(date -u '+%Y%m%d_%H%M%SZ')
OUT_DIR="/tmp/infra_diag_${TIMESTAMP}"
mkdir -p "${OUT_DIR}"

echo "============================================================"
echo " Collecting Infrastructure Diagnostics"
echo " Destination: ${OUT_DIR}"
echo " Timestamp: ${TIMESTAMP}"
echo "============================================================"

# 1. Host Identity & Uptime
echo "[1/7] Gathering host metadata and uptime..."
{
    echo "=== Host Information ==="
    hostnamectl 2>/dev/null || uname -a
    echo ""
    echo "=== Uptime & Load Average ==="
    uptime
} > "${OUT_DIR}/01_host_uptime.txt"

# 2. Resource Utilization (CPU & Memory)
echo "[2/7] Capturing CPU, memory and swap utilization..."
{
    echo "=== Memory Usage ==="
    free -m
    echo ""
    echo "=== Virtual Memory Stats ==="
    vmstat 1 3 2>/dev/null || true
    echo ""
    echo "=== Top 15 CPU Consumers ==="
    ps aux --sort=-%cpu | head -n 16
    echo ""
    echo "=== Top 15 Memory Consumers ==="
    ps aux --sort=-%mem | head -n 16
} > "${OUT_DIR}/02_resources.txt"

# 3. Storage & Filesystem Health
echo "[3/7] Checking storage, mount points and inode utilization..."
{
    echo "=== Disk Space (Human-readable) ==="
    df -h
    echo ""
    echo "=== Inode Usage ==="
    df -i
} > "${OUT_DIR}/03_storage.txt"

# 4. Networking, Routing & Sockets
echo "[4/7] Inspecting network interfaces, routing tables and listening sockets..."
{
    echo "=== Network Interfaces ==="
    ip -s link 2>/dev/null || ifconfig
    echo ""
    echo "=== IP Addresses ==="
    ip -4 addr 2>/dev/null || true
    ip -6 addr 2>/dev/null || true
    echo ""
    echo "=== Routing Table ==="
    ip route show 2>/dev/null || netstat -rn
    echo ""
    echo "=== Listening Sockets ==="
    ss -tulpn 2>/dev/null || netstat -tulpn 2>/dev/null || true
} > "${OUT_DIR}/04_networking.txt"

# 5. systemd & Process Health
echo "[5/7] Checking systemd service status and failed units..."
{
    echo "=== Failed systemd Units ==="
    systemctl --failed 2>/dev/null || true
    echo ""
    echo "=== System Status ==="
    systemctl is-system-running 2>/dev/null || true
} > "${OUT_DIR}/05_systemd.txt"

# 6. Kernel & Hardware Errors
echo "[6/7] Extracting recent kernel errors (dmesg)..."
{
    echo "=== Recent dmesg Errors ==="
    dmesg -T -l err,crit,alert,emerg 2>/dev/null || dmesg | tail -n 100
} > "${OUT_DIR}/06_kernel_errors.txt"

# 7. DNS & Core Connectivity Test
echo "[7/7] Probing DNS resolution and gateway reachability..."
{
    echo "=== DNS Resolver Configuration ==="
    cat /etc/resolv.conf 2>/dev/null || true
    echo ""
    echo "=== Gateway Ping Test ==="
    GW=$(ip route | grep default | awk '{print $3}' | head -n 1 || true)
    if [ -n "${GW}" ]; then
        echo "Pinging default gateway: ${GW}"
        ping -c 3 -W 2 "${GW}" || echo "Gateway ping failed"
    else
        echo "No default gateway found in routing table."
    fi
} > "${OUT_DIR}/07_connectivity.txt"

# Summary
echo "============================================================"
echo " Diagnostic bundle created at: ${OUT_DIR}"
echo " Files collected:"
ls -lh "${OUT_DIR}"
echo "============================================================"
