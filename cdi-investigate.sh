#!/bin/bash
echo "=== Checking CDI Configuration on myvm000000 ==="
echo "Date: $(date)"
echo

echo "1. Checking if CDI is enabled in containerd config:"
echo "--- Looking for CDI configuration ---"
grep -A 5 -B 5 -i cdi /etc/containerd/config.toml || echo "No CDI configuration found in containerd config"
echo

echo "2. Checking crictl info for CDI status:"
crictl info | jq '.config.enableCDI' 2>/dev/null || echo "Could not get CDI status from crictl"
echo

echo "3. Checking CDI directories and files:"
echo "CDI root directory (/var/run/cdi):"
ls -la /var/run/cdi/ 2>/dev/null || echo "/var/run/cdi does not exist"
echo

echo "Alternative CDI location (/etc/cdi):"
ls -la /etc/cdi/ 2>/dev/null || echo "/etc/cdi does not exist"
echo

echo "4. Looking for any CDI spec files created by DRA driver:"
find /var/run/cdi /etc/cdi -name "*.json" 2>/dev/null | head -10 || echo "No CDI JSON files found"
echo

echo "5. Checking containerd systemd service configuration:"
systemctl cat containerd | grep -i cdi || echo "No CDI-related config in containerd service"
echo

echo "=== CDI Investigation Complete ==="