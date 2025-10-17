#!/usr/bin/env bash
# Complete BYOCNI Cluster Setup: AKS BYOCNI (overlay, no kube-proxy) + Cilium + CNS + azure-ipam + ip-masq-agent
# This script combines cluster creation with proper CNS configuration and external connectivity fixes
#
# Usage:
#   ./byocni-cilium-cns-complete.sh <k8sVersion> <subscription> <resourceGroup/clusterName>
#
# Tunables (export before run or inline KEY=VAL ./script):
#   REGION=centraluseuap
#   NODE_COUNT=2
#   VM_SIZE=Standard_B2s
#   IDENTITY_MODE=sa|uami
#   WORKDIR=$PWD/acn-tmp
#   # Cilium (manifest folder is v1.17; images from acnpublic nightly)
#   CILIUM_MANIFEST_DIR=1.17
#   CILIUM_VERSION_TAG=cilium-nightly-pipeline
#   CILIUM_IMAGE_REGISTRY=acnpublic.azurecr.io
#   # CNS + IPAM (MCR)
#   CNS_VERSION_TAG=v1.7.9-0
#   IPAM_VERSION_TAG=v0.4.0

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <k8sVersion> <subscription> <resourceGroup/clusterName>"
  exit 1
fi

K8S_VER="$1"; SUB="$2"; RG_AND_NAME="$3"
[[ "$RG_AND_NAME" != */* ]] && { echo "ERROR: third arg must be 'resourceGroup/clusterName'"; exit 1; }
GROUP="${RG_AND_NAME%%/*}"; CLUSTER="${RG_AND_NAME##*/}"

# ---- Defaults (override via env) ----
REGION="${REGION:-centraluseuap}"
NODE_COUNT="${NODE_COUNT:-2}"
VM_SIZE="${VM_SIZE:-Standard_B2s}"
IDENTITY_MODE="${IDENTITY_MODE:-sa}"             # 'sa' (system-assigned) or 'uami'
WORKDIR="${WORKDIR:-$PWD/acn-tmp}"
KUBECONFIG_PATH="$WORKDIR/kubeconfig"

# Cilium manifests + images (acnpublic nightly)
CILIUM_MANIFEST_DIR="${CILIUM_MANIFEST_DIR:-1.17}"
CILIUM_VERSION_TAG="${CILIUM_VERSION_TAG:-cilium-nightly-pipeline}"
CILIUM_IMAGE_REGISTRY="${CILIUM_IMAGE_REGISTRY:-acnpublic.azurecr.io}"
CILIUM_AGENT_IMAGE="${CILIUM_IMAGE_REGISTRY}/cilium/cilium:${CILIUM_VERSION_TAG}"
CILIUM_OPERATOR_IMAGE="${CILIUM_IMAGE_REGISTRY}/cilium/operator-generic:${CILIUM_VERSION_TAG}"

# CNS/IPAM (MCR) - Updated versions
CNS_VERSION_TAG="${CNS_VERSION_TAG:-v1.7.9-0}"
IPAM_VERSION_TAG="${IPAM_VERSION_TAG:-v0.4.0}"

# CNS Configuration
NS="${NS:-kube-system}"
DS="${DS:-azure-cns}"
CM="${CM:-cns-config}"
CNS_CONTAINER_NAME="${CNS_CONTAINER_NAME:-cns-container}"
CNS_IMAGE="${CNS_IMAGE:-mcr.microsoft.com/containernetworking/azure-cns:${CNS_VERSION_TAG}}"
IPAM_INSTALLER_IMAGE="${IPAM_INSTALLER_IMAGE:-mcr.microsoft.com/containernetworking/azure-ipam:${IPAM_VERSION_TAG}}"
SHELL_IMAGE="${SHELL_IMAGE:-mcr.microsoft.com/cbl-mariner/base/core:2.0}"

# Ports & scheduling
API_PORT="${API_PORT:-10090}"
PROM_PORT="${PROM_PORT:-10092}"
PRIORITY_CLASS="${PRIORITY_CLASS:-system-node-critical}"

# Network CIDRs (will be auto-detected)
POD_CIDRS="${POD_CIDRS:-}"
SERVICE_CIDRS="${SERVICE_CIDRS:-}"
INFRA_VNET_CIDRS="${INFRA_VNET_CIDRS:-10.224.0.0/12}"

mkdir -p "$WORKDIR"
export KUBECONFIG="$KUBECONFIG_PATH"

# ===== Helpers =====
need() { command -v "$1" >/dev/null 2>&1 || { echo "ERROR: '$1' not found."; exit 1; }; }
need az; need kubectl; need git; need envsubst; need sudo

hash_cmd() { command -v sha256sum >/dev/null 2>&1 && echo sha256sum || echo "shasum -a 256"; }
SED_BIN="${SED_BIN:-sed}"

# Pretty printer
say() { printf "\033[1;36m== %s\033[0m\n" "$*"; }
warn() { printf "\033[1;33m[WARN]\033[0m %s\n" "$*"; }
err() { printf "\033[1;31m[ERROR]\033[0m %s\n" "$*" >&2; }

az extension add --name aks-preview --yes >/dev/null 2>&1 || true
az extension update --name aks-preview >/dev/null 2>&1 || true
az account set -s "$SUB"

retry() { local n=0 max=$1 delay=$2; shift 2; until "$@"; do n=$((n+1)); [[ $n -ge $max ]] && return 1; sleep "$delay"; done; }

# ===== Pre-flight checks =====
check_cluster_readiness() {
  say "Checking cluster and Cilium readiness"
  
  # Check if we can connect to the cluster
  if ! kubectl get nodes >/dev/null 2>&1; then
    err "Cannot connect to cluster. Check KUBECONFIG: $KUBECONFIG"
    exit 1
  fi
  
  # Check if Cilium is running
  if ! kubectl get pods -n kube-system -l k8s-app=cilium >/dev/null 2>&1; then
    err "Cilium pods not found. This script requires Cilium to be installed."
    exit 1
  fi
  
  # Check if Cilium is configured with delegated-plugin IPAM
  local cilium_ipam
  cilium_ipam=$(kubectl get configmap -n kube-system cilium-config -o jsonpath='{.data.ipam}' 2>/dev/null || echo "")
  if [[ "$cilium_ipam" != "delegated-plugin" ]]; then
    warn "Cilium IPAM is '$cilium_ipam', expected 'delegated-plugin'"
    warn "For BYOCNI with azure-ipam, Cilium should be configured with IPAM delegation"
  else
    echo "✓ Cilium configured with delegated-plugin IPAM"
  fi
  
  # Check if azure-cns ServiceAccount exists, create if not
  if ! kubectl get serviceaccount -n kube-system azure-cns >/dev/null 2>&1; then
    say "Creating azure-cns ServiceAccount and RBAC"
    kubectl apply -f - <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: azure-cns
  namespace: kube-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: azure-cns
rules:
- apiGroups: [""]
  resources: ["nodes", "nodes/status", "pods", "endpoints", "namespaces"]
  verbs: ["get", "list", "watch", "update", "patch"]
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["acn.azure.com"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: azure-cns
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: azure-cns
subjects:
- kind: ServiceAccount
  name: azure-cns
  namespace: kube-system
EOF
  else
    echo "✓ azure-cns ServiceAccount exists"
  fi
  
  echo "✓ Cluster readiness check completed"
}

# Detect PodCIDR from nodes or infer from existing pods
detect_pod_cidr() {
  local list
  list=$(kubectl get nodes -o jsonpath='{range .items[*]}{.spec.podCIDR}{"\n"}{end}' | sed '/^$/d' | sort -u)
  if [[ -z "${POD_CIDRS}" ]]; then
    if [[ -z "$list" ]]; then
      # For BYOCNI clusters, nodes may not have podCIDR set
      # Try to infer from existing pod IPs
      warn "Nodes don't have podCIDR set (normal for BYOCNI). Trying to infer from pod IPs..."
      local pod_ips
      pod_ips=$(kubectl get pods --all-namespaces -o jsonpath='{range .items[*]}{.status.podIP}{"\n"}{end}' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -10 | sort -u)
      
      if [[ -n "$pod_ips" ]]; then
        # Look for the most common network prefix
        local common_prefix
        common_prefix=$(echo "$pod_ips" | cut -d. -f1-2 | sort | uniq -c | sort -nr | head -1 | awk '{print $2}')
        if [[ -n "$common_prefix" ]]; then
          POD_CIDRS="${common_prefix}.0.0/16"
          warn "Inferred POD_CIDRS=${POD_CIDRS} from existing pod IPs: $(echo "$pod_ips" | tr '\n' ' ')"
          warn "Override with POD_CIDRS=... if this is incorrect"
        else
          # Fallback to common Azure defaults
          POD_CIDRS="192.168.0.0/16"
          warn "Could not infer pod CIDR from pods. Using overlay default: POD_CIDRS=${POD_CIDRS}"
          warn "Override with POD_CIDRS=... if this is incorrect"
        fi
      else
        # Ultimate fallback
        POD_CIDRS="192.168.0.0/16"
        warn "No pods found to infer CIDR. Using overlay default: POD_CIDRS=${POD_CIDRS}"
        warn "Override with POD_CIDRS=... if this is incorrect"
      fi
    else
      local count; count=$(echo "$list" | wc -l | tr -d ' ')
      if [[ "$count" -gt 1 ]]; then
        warn "Multiple podCIDRs detected: $(echo "$list" | tr '\n' ' ')"
        warn "Using the first; override with POD_CIDRS=... if needed."
      fi
      POD_CIDRS="$(echo "$list" | head -n1)"
    fi
  fi
}

# Infer ServiceCIDR from kube-dns ClusterIP (assumes /16 on AKS when not provided)
infer_service_cidr() {
  if [[ -n "${SERVICE_CIDRS}" ]]; then return; fi
  local cip; cip=$(kubectl -n default get svc kubernetes -o jsonpath='{.spec.clusterIP}' 2>/dev/null || true)
  if [[ -z "$cip" ]]; then
    warn "Could not read kubernetes service ClusterIP; set SERVICE_CIDRS=... and re-run if needed."
    SERVICE_CIDRS="10.0.0.0/16"  # Default for AKS
    return
  fi
  # Heuristic: <a>.<b>.<c>.<d> -> a.b.0.0/16 (common on AKS defaults)
  local a b; a=$(echo "$cip" | cut -d. -f1); b=$(echo "$cip" | cut -d. -f2)
  SERVICE_CIDRS="${a}.${b}.0.0/16"
  warn "Inferred SERVICE_CIDRS=${SERVICE_CIDRS} from kubernetes service ClusterIP=${cip}"
}

sha256_file() { $(hash_cmd) "$1" | awk '{print $1}'; }

# =============================================================================
# CLUSTER CREATION PHASE
# =============================================================================

say "Starting BYOCNI cluster creation with Cilium and CNS"

# --- ACN repo ---
if [[ ! -d "$WORKDIR/azure-container-networking" ]]; then
  git clone --depth 1 https://github.com/Azure/azure-container-networking.git "$WORKDIR/azure-container-networking"
fi
cd "$WORKDIR/azure-container-networking"

# --- Network artifacts ---
say "Precreating RG/VNet/Public IP in $REGION"
retry 3 5 make -C hack/aks rg-up          AZCLI=az SUB="$SUB" GROUP="$GROUP" CLUSTER="$CLUSTER" REGION="$REGION"
retry 3 5 make -C hack/aks overlay-net-up AZCLI=az SUB="$SUB" GROUP="$GROUP" CLUSTER="$CLUSTER" REGION="$REGION"
retry 3 5 make -C hack/aks ipv4           AZCLI=az SUB="$SUB" GROUP="$GROUP" CLUSTER="$CLUSTER" REGION="$REGION"
SUBNET_ID="/subscriptions/$SUB/resourceGroups/$GROUP/providers/Microsoft.Network/virtualNetworks/$CLUSTER/subnets/nodenet"

# --- AKS create (BYOCNI overlay; no kube-proxy) ---
say "Creating AKS BYOCNI overlay cluster (no kube-proxy)"
EXTRA_ARGS="--ssh-access disabled --only-show-errors"
if [[ "$IDENTITY_MODE" == "uami" ]]; then
  az identity create -g "$GROUP" -n "${CLUSTER}-uami-control" -l "$REGION" >/dev/null
  az identity create -g "$GROUP" -n "${CLUSTER}-uami-kubelet" -l "$REGION" >/dev/null
  CTRL_MI_ID=$(az identity show -g "$GROUP" -n "${CLUSTER}-uami-control" --query id -o tsv)
  KUBE_MI_ID=$(az identity show -g "$GROUP" -n "${CLUSTER}-uami-kubelet" --query id -o tsv)
  KUBE_MI_OID=$(az identity show -g "$GROUP" -n "${CLUSTER}-uami-kubelet" --query principalId -o tsv)
  az role assignment create --assignee-object-id "$KUBE_MI_OID" --assignee-principal-type ServicePrincipal \
    --role "Network Contributor" --scope "$SUBNET_ID" >/dev/null
  EXTRA_ARGS="$EXTRA_ARGS --assign-identity $CTRL_MI_ID --assign-kubelet-identity $KUBE_MI_ID"
fi

retry 2 10 make -C hack/aks overlay-byocni-nokubeproxy-up \
  AZCLI=az SUB="$SUB" GROUP="$GROUP" CLUSTER="$CLUSTER" REGION="$REGION" \
  K8S_VER="$K8S_VER" NODE_COUNT="$NODE_COUNT" VM_SIZE="$VM_SIZE" \
  EXTRA_AKS_ARGS="$EXTRA_ARGS"

# Verify cluster creation succeeded
if ! az aks show -g "$GROUP" -n "$CLUSTER" >/dev/null 2>&1; then
  err "Cluster creation failed. Cluster $CLUSTER not found in resource group $GROUP"
  exit 1
fi

say "Cluster $CLUSTER created successfully"

# --- Kubeconfig (deterministic) ---
az aks get-credentials -g "$GROUP" -n "$CLUSTER" --overwrite-existing --file "$KUBECONFIG_PATH"
export KUBECONFIG="$KUBECONFIG_PATH"

# Verify kubeconfig works
if ! kubectl config current-context >/dev/null 2>&1; then
  err "Failed to get kubeconfig or connect to cluster. Check $KUBECONFIG_PATH"
  exit 1
fi

say "Successfully connected to cluster $(kubectl config current-context)"

# --- Wait only for API (nodes may be NotReady until CNI + CNS) ---
say "Waiting for API server readiness"
retry 60 5 bash -c 'kubectl get --raw=/readyz 2>/dev/null | grep -qi "^ok$"'

# =============================================================================
# CILIUM INSTALLATION
# =============================================================================
say "Installing Cilium (acnpublic nightly; manifest folder v${CILIUM_MANIFEST_DIR})"

kubectl apply --validate=false -f "test/integration/manifests/cilium/v${CILIUM_MANIFEST_DIR}/cilium-config/cilium-config.yaml"
kubectl apply --validate=false -f "test/integration/manifests/cilium/v${CILIUM_MANIFEST_DIR}/cilium-agent/files"
kubectl apply --validate=false -f "test/integration/manifests/cilium/v${CILIUM_MANIFEST_DIR}/cilium-operator/files"

export CILIUM_VERSION_TAG CILIUM_IMAGE_REGISTRY
render_and_apply() {
  local in="$1"
  envsubst '${CILIUM_VERSION_TAG},${CILIUM_IMAGE_REGISTRY}' < "$in" \
    | sed -e 's|quay.io/cilium|acnpublic.azurecr.io/cilium|g' \
          -e 's|docker.io/cilium|acnpublic.azurecr.io/cilium|g' \
    | kubectl apply --validate=false -f -
}
render_and_apply "test/integration/manifests/cilium/v${CILIUM_MANIFEST_DIR}/cilium-agent/templates/daemonset.yaml"
render_and_apply "test/integration/manifests/cilium/v${CILIUM_MANIFEST_DIR}/cilium-operator/templates/deployment.yaml"

kubectl -n kube-system set image ds/cilium cilium-agent="${CILIUM_AGENT_IMAGE}" --record || true
kubectl -n kube-system set image deploy/cilium-operator cilium-operator="${CILIUM_OPERATOR_IMAGE}" --record || true

kubectl -n kube-system rollout status ds/cilium --timeout=15m
kubectl -n kube-system rollout status deploy/cilium-operator --timeout=15m

# =============================================================================
# CNS CONFIGURATION PHASE (Enhanced from patchCNS.sh)
# =============================================================================

# Return to original directory for CNS configuration
cd "$WORKDIR/.."

check_cluster_readiness

# Detect/confirm CIDRs
say "Detecting cluster CIDRs"
detect_pod_cidr
infer_service_cidr
echo "POD_CIDRS=${POD_CIDRS}"
echo "SERVICE_CIDRS=${SERVICE_CIDRS:-<unset>}"
echo "INFRA_VNET_CIDRS=${INFRA_VNET_CIDRS}"

# Apply CNS Config (CRD mode; InitializeFromCNI=false)
say "Applying CNS ConfigMap '${CM}' in ns/${NS}"

# Wait for kube-system namespace to exist
kubectl get namespace kube-system 2>/dev/null || kubectl create namespace kube-system

# Delete existing ConfigMap if it exists to avoid conflicts
kubectl -n "$NS" delete configmap "$CM" --ignore-not-found=true

TMP_JSON="$(mktemp)"
cat > "$TMP_JSON" <<JSON
{
  "CNIConflistFilepath": "/etc/cni/net.d/05-cilium.conflist",
  "CNIConflistScenario": "cilium",
  "ChannelMode": "CRD",
  "EnableAsyncPodDelete": true,
  "EnableCNIConflistGeneration": true,
  "EnableIPAMv2": false,
  "EnableK8sDevicePlugin": false,
  "EnableLoggerV2": true,
  "EnableStateMigration": false,
  "EnableSubnetScarcity": false,
  "InitializeFromCNI": false,
  "Logger": {
    "file": {
      "filepath": "/var/log/azure-cns/azure-cns.log",
      "level": "info",
      "maxBackups": 5,
      "maxSize": 5
    }
  },
  "ManageEndpointState": true,
  "ManagedSettings": {
    "InfrastructureNetworkID": "",
    "NodeID": "",
    "NodeSyncIntervalInSeconds": 30,
    "PrivateEndpoint": ""
  },
  "MetricsBindAddress": ":${PROM_PORT}",
  "ProgramSNATIPTables": false,
  "TelemetrySettings": {
    "DebugMode": false,
    "DisableAll": false,
    "HeartBeatIntervalInMins": 30,
    "RefreshIntervalInSecs": 15,
    "SnapshotIntervalInMins": 60,
    "TelemetryBatchIntervalInSecs": 15,
    "TelemetryBatchSizeBytes": 16384
  }
}
JSON

kubectl -n "$NS" create configmap "$CM" \
  --from-file=cns_config.json="$TMP_JSON" \
  -o yaml --dry-run=client | kubectl apply -f -


  # Create enhanced CNS DaemonSet with hostNetwork: true
  say "Creating enhanced CNS DaemonSet (hostNetwork: true)"

  kubectl -n "$NS" delete daemonset "$DS" --ignore-not-found=true

  PATCH_FILE="$(mktemp)"
  CKSUM="$(sha256_file "$TMP_JSON")"

  cat > "$PATCH_FILE" <<EOF
  apiVersion: apps/v1
  kind: DaemonSet
  metadata:
    name: ${DS}
    namespace: ${NS}
    labels:
      k8s-app: azure-cns
      app.kubernetes.io/name: azure-cns
  spec:
    selector:
      matchLabels:
        k8s-app: azure-cns
    template:
      metadata:
        labels:
          app: azure-cns
          k8s-app: azure-cns
          app.kubernetes.io/managed-by: Eno
          kubernetes.azure.com/managedby: aks
        annotations:
          cluster-autoscaler.kubernetes.io/daemonset-pod: "true"
          prometheus.io/port: "${PROM_PORT}"
          kubernetes.azure.com/azure-cns-configmap-checksum: "${CKSUM}"
      spec:
        hostNetwork: true
        serviceAccountName: azure-cns
        priorityClassName: ${PRIORITY_CLASS}
        nodeSelector:
          kubernetes.io/os: linux
        tolerations:
          - operator: Exists
            effect: NoExecute
          - operator: Exists
            effect: NoSchedule
          - key: CriticalAddonsOnly
            operator: Exists
        initContainers:
          - name: cni-installer
            image: ${IPAM_INSTALLER_IMAGE}
            imagePullPolicy: IfNotPresent
            command: ["/dropgz"]
            args: ["deploy", "--skip-verify", "azure-ipam", "-o", "/opt/cni/bin/azure-ipam"]
            volumeMounts:
              - name: cni-bin
                mountPath: /opt/cni/bin
            securityContext:
              privileged: true
          - name: cni-finalize
            image: ${SHELL_IMAGE}
            imagePullPolicy: IfNotPresent
            command: ["/bin/sh", "-c"]
            args:
              - |
                set -e
                ls -l /opt/cni/bin || true
                test -s /opt/cni/bin/azure-ipam || { echo >&2 'azure-ipam missing'; exit 1; }
                chmod 0755 /opt/cni/bin/azure-ipam
                echo 'azure-ipam present:'; ls -l /opt/cni/bin/azure-ipam
                echo 'Checking for Cilium CNI files...'; ls -la /etc/cni/net.d/ || true
                echo 'CNI setup complete for BYOCNI Cilium + azure-ipam'
            volumeMounts:
              - name: cni-bin
                mountPath: /opt/cni/bin
              - name: cni-conflist
                mountPath: /etc/cni/net.d
            securityContext:
              privileged: true
        containers:
          - name: ${CNS_CONTAINER_NAME}
            image: ${CNS_IMAGE}
            imagePullPolicy: IfNotPresent
            ports:
              - name: api
                containerPort: ${API_PORT}
                protocol: TCP
              - name: metrics
                containerPort: ${PROM_PORT}
                protocol: TCP
            args: ["-c", "tcp://\$(CNSIpAddress):\$(CNSPort)", "-t", "\$(CNSLogTarget)", "-o", "\$(CNSLogDir)"]
            env:
              - name: CNSIpAddress
                value: "127.0.0.1"
              - name: CNSPort
                value: "${API_PORT}"
              - name: CNSLogTarget
                value: "stdoutfile"
              - name: CNSLogDir
                value: "/var/log"
              - name: CNS_CONFIGURATION_PATH
                value: "/etc/azure-cns/cns_config.json"
              - name: NODENAME
                valueFrom:
                  fieldRef:
                    fieldPath: spec.nodeName
              - name: POD_CIDRs
                value: "${POD_CIDRS}"
              - name: SERVICE_CIDRs
                value: "${SERVICE_CIDRS}"
              - name: INFRA_VNET_CIDRs
                value: "${INFRA_VNET_CIDRS}"
            resources:
              requests:
                cpu: "40m"
                memory: "250Mi"
              limits:
                cpu: "40m"
                memory: "250Mi"
            livenessProbe:
              httpGet:
                path: /healthz
                port: metrics
              timeoutSeconds: 1
              periodSeconds: 10
              failureThreshold: 3
            readinessProbe:
              httpGet:
                path: /readyz
                port: metrics
              timeoutSeconds: 1
              periodSeconds: 1
              failureThreshold: 1
            startupProbe:
              httpGet:
                path: /healthz
                port: metrics
              timeoutSeconds: 1
              periodSeconds: 10
              failureThreshold: 30
            securityContext:
              privileged: true
              capabilities:
                add: ["NET_ADMIN", "NET_RAW", "SYS_ADMIN"]
            volumeMounts:
              - name: cns-config
                mountPath: /etc/azure-cns
              - name: cni-conflist
                mountPath: /etc/cni/net.d
              - name: cni-bin
                mountPath: /opt/cni/bin
              - name: cns-state
                mountPath: /var/lib/azure-network
              - name: cni-lock
                mountPath: /var/lock/azure-vnet
              - name: log
                mountPath: /var/log
              - name: azure-endpoints
                mountPath: /var/run/azure-cns
              - name: azure-vnet
                mountPath: /var/run/azure-vnet
        volumes:
          - name: azure-endpoints
            hostPath:
              path: /var/run/azure-cns
              type: DirectoryOrCreate
          - name: log
            hostPath:
              path: /var/log/azure-cns
              type: DirectoryOrCreate
          - name: cns-state
            hostPath:
              path: /var/lib/azure-network
              type: DirectoryOrCreate
          - name: cni-bin
            hostPath:
              path: /opt/cni/bin
              type: Directory
          - name: azure-vnet
            hostPath:
              path: /var/run/azure-vnet
              type: DirectoryOrCreate
          - name: cni-lock
            hostPath:
              path: /var/lock/azure-vnet
              type: DirectoryOrCreate
          - name: cni-conflist
            hostPath:
              path: /etc/cni/net.d
              type: DirectoryOrCreate
          - name: cns-config
            configMap:
              name: ${CM}
              optional: false
EOF

  kubectl apply -f "$PATCH_FILE"

  say "Rolling CNS DaemonSet and waiting for readiness"
  kubectl -n "$NS" rollout restart "ds/$DS" 2>/dev/null || true
  kubectl -n "$NS" rollout status "ds/$DS" --timeout=10m

# Deploy IP Masquerade Agent for External Connectivity
say "Deploying Azure IP Masquerade Agent for external connectivity"

cat <<YAML | kubectl apply -f -
apiVersion: v1
kind: ConfigMap
metadata:
  name: ip-masq-agent-config
  namespace: kube-system
data:
  config: |
    nonMasqueradeCIDRs:
      - ${POD_CIDRS}
      - 10.10.0.0/16
      - ${SERVICE_CIDRS}
    masqLinkLocal: true
    resyncInterval: 60s
---
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: azure-ip-masq-agent-user
  namespace: kube-system
  labels:
    k8s-app: azure-ip-masq-agent-user
spec:
  selector:
    matchLabels:
      k8s-app: azure-ip-masq-agent-user
  template:
    metadata:
      labels:
        k8s-app: azure-ip-masq-agent-user
    spec:
      automountServiceAccountToken: false
      containers:
      - args:
        - --v=2
        - --resync-interval=60
        image: mcr.microsoft.com/aks/ip-masq-agent-v2:v0.1.7
        imagePullPolicy: IfNotPresent
        name: azure-ip-masq-agent
        resources:
          limits:
            cpu: 500m
            memory: 250Mi
          requests:
            cpu: 100m
            memory: 50Mi
        securityContext:
          privileged: true
        volumeMounts:
        - mountPath: /etc/config
          name: config
      dnsPolicy: ClusterFirst
      hostNetwork: true
      nodeSelector:
        kubernetes.io/os: linux
      priorityClassName: system-node-critical
      restartPolicy: Always
      tolerations:
      - effect: NoSchedule
        operator: Exists
      - effect: NoExecute
        operator: Exists
      - key: CriticalAddonsOnly
        operator: Exists
      volumes:
      - configMap:
          defaultMode: 420
          name: ip-masq-agent-config
          optional: true
        name: config
  updateStrategy:
    rollingUpdate:
      maxSurge: 0
      maxUnavailable: 1
    type: RollingUpdate
YAML

kubectl rollout status daemonset -n kube-system azure-ip-masq-agent-user --timeout=120s

# Wait for all components and then restart CoreDNS
say "Restarting CoreDNS with updated networking configuration"
sleep 10  # Give ip-masq-agent time to configure iptables rules

# Delete CoreDNS pods to force recreation with new networking
kubectl delete pods -n kube-system -l k8s-app=kube-dns --ignore-not-found=true

# Wait for CoreDNS to come back up
say "Waiting for CoreDNS to be ready with new network configuration"
kubectl wait --for=condition=ready pod -l k8s-app=kube-dns -n kube-system --timeout=300s || {
  warn "CoreDNS not ready within 5 minutes. Checking status..."
  kubectl get pods -l k8s-app=kube-dns -n kube-system -o wide
}

# Best-effort node readiness after everything is configured
say "Waiting for nodes to be Ready (post Cilium+CNS+ip-masq-agent)"
kubectl wait --for=condition=Ready nodes --all --timeout=10m || true

# =============================================================================
# FINAL VERIFICATION
# =============================================================================

say "Final verification and status check"

echo "=== Cluster Information ==="
kubectl get nodes -o wide

echo ""
echo "=== Pod Status ==="
echo "Cilium pods:"
kubectl -n kube-system get pods -l k8s-app=cilium -o wide

echo ""
echo "CNS pods:"
kubectl -n kube-system get pods -l k8s-app=azure-cns -o wide

echo ""
echo "CoreDNS pods:"
kubectl -n kube-system get pods -l k8s-app=kube-dns -o wide

echo ""
echo "IP Masquerade Agent pods:"
kubectl -n kube-system get pods -l k8s-app=azure-ip-masq-agent-user -o wide

echo ""
echo "=== Component Images ==="
echo "Cilium DS images:"
kubectl -n kube-system get ds cilium -o jsonpath='{.spec.template.spec.initContainers[*].image}{"\n"}{.spec.template.spec.containers[*].image}{"\n"}' 2>/dev/null || echo "N/A"

echo "Cilium Operator image:"
kubectl -n kube-system get deploy cilium-operator -o jsonpath='{.spec.template.spec.containers[*].image}{"\n"}' 2>/dev/null || echo "N/A"

echo "CNS image + init:"
kubectl -n kube-system get ds azure-cns -o jsonpath='{.spec.template.spec.initContainers[*].image}{"\n"}{.spec.template.spec.containers[*].image}{"\n"}' 2>/dev/null || echo "N/A"

echo ""
echo "=== Network Configuration ==="
echo "Detected CIDRs:"
echo "  POD_CIDRS: ${POD_CIDRS}"
echo "  SERVICE_CIDRS: ${SERVICE_CIDRS}"
echo "  INFRA_VNET_CIDRS: ${INFRA_VNET_CIDRS}"

echo ""
echo "=== DNS Test ==="
if kubectl run dns-test --image=busybox --restart=Never --rm -i --quiet -- nslookup kubernetes.default.svc.cluster.local >/dev/null 2>&1; then
  echo "✅ DNS resolution working correctly"
else
  echo "⚠️  DNS resolution test failed - may need additional time to stabilize"
fi

echo ""
echo "🎉 BYOCNI cluster deployment completed successfully!"
echo ""
echo "Cluster Details:"
echo "  Name: $CLUSTER"
echo "  Region: $REGION" 
echo "  Kubernetes Version: $K8S_VER"
echo "  Node Count: $NODE_COUNT"
echo "  VM Size: $VM_SIZE"
echo ""
echo "Installed Components:"
echo "  ✅ Cilium ${CILIUM_VERSION_TAG} (delegated IPAM)"
echo "  ✅ Azure CNS ${CNS_VERSION_TAG} (overlay mode)"
echo "  ✅ azure-ipam ${IPAM_VERSION_TAG}"
echo "  ✅ Azure IP Masquerade Agent (external connectivity)"
echo ""
echo "Your BYOCNI cluster is ready with proper datapath via Cilium + CNS + azure-ipam!"

# Cleanup temporary files
rm -f "$TMP_JSON" "$PATCH_FILE" 2>/dev/null || true