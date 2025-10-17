#!/bin/bash

# Kubelet DRA Registration Monitor
# This script monitors for DRA registration issues and restarts kubelet when needed

KUBECONFIG_PATH="/home/behzadm/e2eStandalone-2nd/standalone/dra/kubeconfig-cosmic/kube"
DRIVER_NAME="dra-secondarynic"
CHECK_INTERVAL=30  # seconds
MAX_FAILURES=3    # restart kubelet after this many consecutive failures

log_msg() {
    echo "[$(date)] $1"
}

check_dra_registration() {
    # Check if there are pods stuck with DRA registration errors
    local failed_pods=$(kubectl --kubeconfig="$KUBECONFIG_PATH" get events --field-selector type=Warning,reason=FailedPrepareDynamicResources --sort-by='.lastTimestamp' -o json 2>/dev/null | jq -r '.items[] | select(.message | contains("'$DRIVER_NAME' is not registered")) | select((.lastTimestamp | fromdateiso8601) > (now - 300)) | .involvedObject.name' 2>/dev/null | head -5)
    
    if [ -n "$failed_pods" ]; then
        log_msg "DRA registration failures detected for pods: $(echo $failed_pods | tr '\n' ' ')"
        return 1
    fi
    
    return 0
}

restart_kubelet_on_node() {
    local node=$1
    log_msg "Attempting to restart kubelet on node: $node"
    
    # Use nsenter pod to restart kubelet
    kubectl --kubeconfig="$KUBECONFIG_PATH" exec -it nsenter-w0553s -- bash -c "systemctl restart kubelet" 2>/dev/null
    if [ $? -eq 0 ]; then
        log_msg "Successfully restarted kubelet on node: $node"
        return 0
    else
        log_msg "Failed to restart kubelet on node: $node"
        return 1
    fi
}

main() {
    local consecutive_failures=0
    
    log_msg "Starting DRA registration monitor for driver: $DRIVER_NAME"
    log_msg "Check interval: ${CHECK_INTERVAL}s, Max failures before restart: $MAX_FAILURES"
    
    while true; do
        if check_dra_registration; then
            if [ $consecutive_failures -gt 0 ]; then
                log_msg "DRA registration restored after $consecutive_failures failures"
                consecutive_failures=0
            else
                log_msg "DRA registration healthy"
            fi
        else
            consecutive_failures=$((consecutive_failures + 1))
            log_msg "DRA registration failure detected (count: $consecutive_failures)"
            
            if [ $consecutive_failures -ge $MAX_FAILURES ]; then
                log_msg "Maximum failures reached ($MAX_FAILURES), restarting kubelet..."
                
                if restart_kubelet_on_node "myvm3000007"; then
                    log_msg "Kubelet restart initiated, waiting for stabilization..."
                    sleep 60  # Wait for kubelet to restart and stabilize
                    consecutive_failures=0
                else
                    log_msg "Kubelet restart failed, will retry on next cycle"
                    sleep 10  # Short wait before retry
                fi
            fi
        fi
        
        sleep $CHECK_INTERVAL
    done
}

# Check dependencies
if ! command -v kubectl &> /dev/null; then
    echo "Error: kubectl not found"
    exit 1
fi

if ! command -v jq &> /dev/null; then
    echo "Error: jq not found (required for JSON parsing)"
    exit 1
fi

main "$@"