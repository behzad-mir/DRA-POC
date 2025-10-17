#!/bin/bash
# NRI Investigation Script for BYON Nodes
# Run this script directly on the BYON node via SSH

echo "=== NRI Investigation Script ==="
echo "Node: $(hostname)"
echo "Date: $(date)"
echo

echo "1. Containerd version:"
containerd --version 2>/dev/null || echo "containerd command not found"
echo

echo "2. Containerd configuration:"
if [ -f /etc/containerd/config.toml ]; then
    echo "--- Checking for NRI config ---"
    grep -A 20 -B 5 nri /etc/containerd/config.toml || echo "No NRI config found in config.toml"
    echo
    echo "--- Full containerd config ---"
    cat /etc/containerd/config.toml
else
    echo "/etc/containerd/config.toml not found"
    echo "Looking for containerd configs..."
    find /etc -name "*containerd*" -type f 2>/dev/null
fi
echo

echo "3. NRI directory structure:"
echo "Checking /var/run/nri:"
ls -la /var/run/nri/ 2>/dev/null || echo "/var/run/nri does not exist"
echo
echo "Checking /opt/nri:"  
ls -la /opt/nri/ 2>/dev/null || echo "/opt/nri does not exist"
echo "Checking /opt/nri/plugins:"
ls -la /opt/nri/plugins/ 2>/dev/null || echo "/opt/nri/plugins does not exist"
echo

echo "4. Containerd service status:"
systemctl status containerd --no-pager -l
echo

echo "5. Recent containerd logs:"
journalctl -u containerd -n 30 --no-pager
echo

echo "6. NRI-specific logs:"
journalctl -u containerd --no-pager | grep -i nri | tail -20 || echo "No NRI logs found"
echo

echo "7. CRI runtime info:"
crictl info 2>/dev/null || echo "crictl command failed"
echo

echo "8. Network interfaces (looking for eth1):"
ip link show | grep -E "eth[1-9]" || echo "No secondary eth interfaces found"
echo

echo "9. Processes related to NRI:"
ps aux | grep -i nri | grep -v grep || echo "No NRI processes found"
echo

echo "10. Containerd plugins:"
crictl info 2>/dev/null | grep -A 20 -i plugin || echo "No plugin info available"
echo

echo "=== Investigation Complete ==="