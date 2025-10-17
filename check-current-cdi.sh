#!/bin/bash
echo "=== Examining Current CDI File ==="
echo "Date: $(date)"
echo

echo "CDI file content:"
cat /var/run/cdi/nic-e093a832-3901-49d5-86a4-3ac79e5e1e01.json | jq . 2>/dev/null || cat /var/run/cdi/nic-e093a832-3901-49d5-86a4-3ac79e5e1e01.json

echo
echo "File permissions:"
ls -la /var/run/cdi/nic-e093a832-3901-49d5-86a4-3ac79e5e1e01.json

echo
echo "Containerd service status:"
systemctl is-active containerd
systemctl status containerd --no-pager -l | tail -10

echo
echo "=== CDI File Examination Complete ==="