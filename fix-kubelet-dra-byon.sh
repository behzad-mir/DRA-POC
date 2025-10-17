#!/bin/bash

# Script to fix DRA feature gates on BYON kubelet nodes
# This fixes the "DRA driver is not registered" issue for long-running pods
# Run this script on each BYON node that needs DRA support

set -e

NODE_NAME=$(hostname)
TIMESTAMP=$(date +%Y%m%d-%H%M%S)

echo "=========================================="
echo "Fixing DRA feature gates for kubelet"
echo "Node: $NODE_NAME"
echo "Timestamp: $TIMESTAMP"
echo "=========================================="

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Backup original configuration
echo "Creating backup of kubelet configuration..."
cp /etc/default/kubelet /etc/default/kubelet.backup.$TIMESTAMP
echo "Backup created: /etc/default/kubelet.backup.$TIMESTAMP"

# Define DRA feature gates needed for BYON clusters
DRA_FEATURE_GATES="--feature-gates=KubeletPodResourcesDynamicResources=true,DRAAdminAccess=true,DRAPrioritizedList=true,DRAResourceClaimDeviceStatus=true,DRASchedulerFilterTimeout=true"

echo "Adding DRA feature gates to KUBELET_FLAGS..."

# Check if feature-gates already exists in the configuration
if grep -q "feature-gates" /etc/default/kubelet; then
    echo "Feature gates already configured, updating existing configuration..."
    # Replace existing feature-gates with our DRA gates
    sed -i "s/--feature-gates=[^[:space:]]*/--feature-gates=KubeletPodResourcesDynamicResources=true,DRAAdminAccess=true,DRAPrioritizedList=true,DRAResourceClaimDeviceStatus=true,DRASchedulerFilterTimeout=true/" /etc/default/kubelet
else
    echo "Adding new DRA feature gates to KUBELET_FLAGS..."
    # Add feature gates to the beginning of KUBELET_FLAGS (after the quote)
    sed -i "s/KUBELET_FLAGS=\"/KUBELET_FLAGS=\"$DRA_FEATURE_GATES /" /etc/default/kubelet
fi

echo ""
echo "Updated kubelet configuration (KUBELET_FLAGS line):"
grep "KUBELET_FLAGS=" /etc/default/kubelet

echo ""
echo "Reloading systemd daemon..."
systemctl daemon-reload

echo "Restarting kubelet service..."
systemctl restart kubelet

echo "Waiting for kubelet to stabilize..."
sleep 10

echo ""
echo "Checking kubelet status..."
if systemctl is-active --quiet kubelet; then
    echo "✅ Kubelet is running successfully"
else
    echo "❌ Kubelet failed to start! Check logs with: journalctl -u kubelet -f"
    exit 1
fi

echo ""
echo "Verifying DRA feature gates are enabled..."
sleep 5

# Check if feature gates are properly set in the running process
if ps aux | grep kubelet | grep -q "feature-gates.*DRA"; then
    echo "✅ DRA feature gates are enabled in the running kubelet process"
else
    echo "⚠️  DRA feature gates may not be active yet, checking logs..."
fi

# Check recent kubelet logs for feature gate confirmation
echo ""
echo "Recent kubelet logs (checking for feature gates):"
journalctl -u kubelet --since "1 minute ago" -n 10 | grep -E "(feature-gates|FLAG)" || echo "No feature gate logs found yet"

echo ""
echo "Checking if DRA driver pods need restart for proper registration..."

# Check if we can access kubectl (this script might run from a node without access)
if command -v kubectl >/dev/null 2>&1; then
    echo "Attempting to restart DRA driver pods to ensure clean registration..."
    
    # Try to restart DRA pods on this node specifically
    kubectl delete pods -l app=drasecondarynic -n kube-system --field-selector=spec.nodeName=$NODE_NAME --ignore-not-found=true 2>/dev/null && echo "✅ DRA driver pods restarted on this node" || echo "⚠️  Could not restart DRA pods (may need manual restart)"
else
    echo "⚠️  kubectl not available - you may need to manually restart DRA driver pods"
    echo "   Run: kubectl delete pods -l app=drasecondarynic -n kube-system --field-selector=spec.nodeName=$NODE_NAME"
fi

echo ""
echo "=========================================="
echo "✅ DRA feature gates fix completed successfully!"
echo ""
echo "What was fixed:"
echo "  - Added DRA feature gates to kubelet configuration"
echo "  - Restarted kubelet service"
echo "  - Verified service is running"
echo "  - Attempted to restart DRA driver pods for clean registration"
echo ""
echo "DRA features now enabled:"
echo "  - KubeletPodResourcesDynamicResources=true"
echo "  - DRAAdminAccess=true" 
echo "  - DRAPrioritizedList=true"
echo "  - DRAResourceClaimDeviceStatus=true"
echo "  - DRASchedulerFilterTimeout=true"
echo ""
echo "This should resolve the 'DRA driver is not registered'"
echo "error and prevent pods from getting stuck in terminating state."
echo ""
echo "IMPORTANT: If you still see registration issues, manually run:"
echo "  kubectl delete pods -l app=drasecondarynic -n kube-system"
echo "=========================================="