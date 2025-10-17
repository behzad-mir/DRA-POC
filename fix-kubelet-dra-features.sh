#!/bin/bash

# Script to fix DRA feature gates on BYON kubelet nodes
# Run this script on each BYON node (myvm3000004, myvm3000007)

set -e

echo "Fixing DRA feature gates for kubelet on BYON node..."

# Backup original configuration
sudo cp /etc/default/kubelet /etc/default/kubelet.backup.$(date +%Y%m%d-%H%M%S)

# Add DRA feature gates to KUBELET_FLAGS
DRA_FEATURE_GATES="--feature-gates=KubeletPodResourcesDynamicResources=true,DRAAdminAccess=true,DRAPrioritizedList=true,DRAResourceClaimDeviceStatus=true,DRASchedulerFilterTimeout=true"

# Check if feature-gates already exists in the configuration
if grep -q "feature-gates" /etc/default/kubelet; then
    echo "Feature gates already configured, updating..."
    # Replace existing feature-gates with our DRA gates
    sudo sed -i "s/--feature-gates=[^[:space:]]*/--feature-gates=KubeletPodResourcesDynamicResources=true,DRAAdminAccess=true,DRAPrioritizedList=true,DRAResourceClaimDeviceStatus=true,DRASchedulerFilterTimeout=true/" /etc/default/kubelet
else
    echo "Adding DRA feature gates to KUBELET_FLAGS..."
    # Add feature gates to the end of KUBELET_FLAGS
    sudo sed -i "s/KUBELET_FLAGS=\"\(.*\)\"/KUBELET_FLAGS=\"\1 $DRA_FEATURE_GATES\"/" /etc/default/kubelet
fi

echo "Updated kubelet configuration:"
grep KUBELET_FLAGS /etc/default/kubelet

echo "Reloading systemd and restarting kubelet..."
sudo systemctl daemon-reload
sudo systemctl restart kubelet

echo "Waiting for kubelet to restart..."
sleep 10

echo "Checking kubelet status..."
sudo systemctl status kubelet --no-pager -l

echo "Checking if DRA feature gates are enabled..."
sleep 5
sudo journalctl -u kubelet -n 20 | grep -E "(feature-gates|DRA)" || echo "No DRA-specific logs found yet, may need more time"

echo "DRA feature gates fix completed!"
echo "You should see kubelet restart and DRA functionality should now work properly."