#!/bin/bash
set +ex

KUBE_VERSION=${1:-1.34.0}
AKS_FQDN=$2
BOOTSTRAP_CLIENT_ID=$3
KUBE_CA_CERT=$4
DNS_IP=${5:-10.0.0.10}

RUNC_VERSION="1.2.0"
CONTAINERD_VERSION="1.7.28"
KUBELOGIN_VERSION="0.2.10"
NODE_NAME=$(hostname)

mkdir -p /var/lib/cni
mkdir -p /opt/cni/bin
mkdir -p /etc/cni/net.d
mkdir -p /etc/kubernetes/volumeplugins
mkdir -p /etc/kubernetes/certs
mkdir -p /etc/containerd
mkdir -p /etc/systemd/system/kubelet.service.d
mkdir -p /var/lib/kubelet
mkdir -p /var/lib/containerd/kubelet

curl -LO https://dl.k8s.io/v${KUBE_VERSION}/kubernetes-node-linux-amd64.tar.gz
tar -xvzf kubernetes-node-linux-amd64.tar.gz kubernetes/node/bin/{kubelet,kubectl,kubeadm}
mv kubernetes/node/bin/{kubelet,kubectl,kubeadm} /usr/local/bin/
rm kubernetes-node-linux-amd64.tar.gz

curl -o runc -L https://github.com/opencontainers/runc/releases/download/v1.3.0/runc.amd64
install -m 0555 runc /usr/bin/runc
rm runc
# Don't think this is needed?
# apt-get install -y jq

curl -LO https://github.com/Azure/kubelogin/releases/download/v0.2.10/kubelogin-linux-amd64.zip
unzip kubelogin-linux-amd64.zip
mv bin/linux_amd64/kubelogin /usr/local/bin
rm kubelogin-linux-amd64.zip

# containerd
curl -LO https://github.com/containerd/containerd/releases/download/v1.7.28/containerd-1.7.28-linux-amd64.tar.gz
tar -xvzf containerd-1.7.28-linux-amd64.tar.gz -C /usr
rm containerd-1.7.28-linux-amd64.tar.gz

# Handling CPU and GPU nodes
DEFAULT_RUNTIME=runc
PROCESSOR_TYPE=cpu
count_gpus=$(lspci | grep "NVIDIA" | grep "controller" | wc -l)
if [ "$count_gpus" -gt 0 ];then
  DEFAULT_RUNTIME=nvidia
  PROCESSOR_TYPE=gpu
  # generate CDI
  nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
  echo -e "[info] nvidia runtime installation completed\n"

  useradd -c "NVIDIA Persistence Daemon,,," -U -s /usr/sbin/nologin -d /nonexistent -M nvidia-persistenced
  cat > /etc/systemd/system/nvidia-persistenced.service << EOL
  [Unit]
  Description=NVIDIA Persistence Daemon
  Wants=syslog.target
  StopWhenUnneeded=true
  [Service]
  Type=forking
  ExecStart=/usr/bin/nvidia-persistenced --user nvidia-persistenced --persistence-mode --verbose
  ExecStopPost=/bin/rm -rf /var/run/nvidia-persistenced
  [Install]
  WantedBy=multi-user.target
EOL
  systemctl enable nvidia-persistenced.service
  systemctl restart nvidia-persistenced.service
fi

tee /etc/systemd/system/containerd.service > /dev/null <<EOF
[Unit]
Description=containerd container runtime
Documentation=https://containerd.io
After=network.target local-fs.target
[Service]
ExecStartPre=-/sbin/modprobe overlay
ExecStart=/usr/bin/containerd
Type=notify
Delegate=yes
KillMode=process
Restart=always
RestartSec=5
# Having non-zero Limit*s causes performance problems due to accounting overhead
# in the kernel. We recommend using cgroups to do container-local accounting.
LimitNPROC=infinity
LimitCORE=infinity
LimitNOFILE=infinity
LimitMEMLOCK=infinity
# Comment TasksMax if your systemd version does not supports it.
# Only systemd 226 and above support this version.
TasksMax=infinity
OOMScoreAdjust=-999
[Install]
WantedBy=multi-user.target
EOF

tee /etc/containerd/config.toml > /dev/null <<EOF
version = 2
oom_score = 0
[plugins."io.containerd.grpc.v1.cri"]
        sandbox_image = "mcr.microsoft.com/oss/kubernetes/pause:3.6"
        [plugins."io.containerd.grpc.v1.cri".containerd]
                default_runtime_name = "$DEFAULT_RUNTIME"
                [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc]
                        runtime_type = "io.containerd.runc.v2"
                [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.runc.options]
                        BinaryName = "/usr/bin/runc"
                        SystemdCgroup = true
                [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia]
                        privileged_without_host_devices = false
                        runtime_engine = ""
                        runtime_root = ""
                        runtime_type = "io.containerd.runc.v1"
                [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.nvidia.options]
                        BinaryName = "/usr/bin/nvidia-container-runtime"
                        SystemdCgroup = true
        [plugins."io.containerd.grpc.v1.cri".registry]
                config_path = "/etc/containerd/certs.d"
        [plugins."io.containerd.grpc.v1.cri".registry.headers]
                X-Meta-Source-Client = ["azure/aks"]
[metrics]
        address = "0.0.0.0:10257"
EOF


tee /etc/sysctl.d/999-sysctl-aks.conf > /dev/null <<EOF
# container networking
net.ipv4.ip_forward = 1
net.ipv4.conf.all.forwarding = 1
net.ipv6.conf.all.forwarding = 1
net.bridge.bridge-nf-call-iptables = 1

# refer to https://github.com/kubernetes/kubernetes/blob/75d45bdfc9eeda15fb550e00da662c12d7d37985/pkg/kubelet/cm/container_manager_linux.go#L359-L397
vm.overcommit_memory = 1
kernel.panic = 10
kernel.panic_on_oops = 1
# to ensure node stability, we set this to the PID_MAX_LIMIT on 64-bit systems: refer to https://kubernetes.io/docs/concepts/policy/pid-limiting/
kernel.pid_max = 4194304
# https://github.com/Azure/AKS/issues/772
fs.inotify.max_user_watches = 1048576
# Ubuntu 22.04 has inotify_max_user_instances set to 128, where as Ubuntu 18.04 had 1024.
fs.inotify.max_user_instances = 1024

# This is a partial workaround to this upstream Kubernetes issue:
# https://github.com/kubernetes/kubernetes/issues/41916#issuecomment-312428731
net.ipv4.tcp_retries2=8
net.core.message_burst=80
net.core.message_cost=40
net.core.somaxconn=16384
net.ipv4.tcp_max_syn_backlog=16384
net.ipv4.neigh.default.gc_thresh1=4096
net.ipv4.neigh.default.gc_thresh2=8192
net.ipv4.neigh.default.gc_thresh3=16384
EOF

mkdir -p /opt/image-cred-provider/config/
mkdir -p /opt/image-cred-provider/bin/

touch /opt/image-cred-provider/bin/workload-identity-token

tee /opt/image-cred-provider/config/workload-identity-token.yaml > /dev/null <<EOF
kind: CredentialProviderConfig
apiVersion: kubelet.config.k8s.io/v1
providers:
- name: workload-identity-token
  apiVersion: credentialprovider.kubelet.k8s.io/v1
  matchImages:
  - "*.azurecr.io"
  args:
  - /var/run/workload-identity-token.sock
  defaultCacheDuration: 1m
EOF

# adust flags as desired
tee /etc/default/kubelet > /dev/null <<EOF
KUBELET_NODE_LABELS="kubernetes.azure.com/mode=system,kubernetes.azure.com/role=agent,node.kubernetes.io/exclude-from-external-load-balancers=true,kubernetes.azure.com/managed=false,kubernetes.io/os=linux,nexus.azure.com/rackid=$RACK_IDENTIFIER,nexus.azure.com/processing-unit=$PROCESSOR_TYPE"
KUBELET_FLAGS="--address=0.0.0.0 --anonymous-auth=false --authentication-token-webhook=true --authorization-mode=Webhook --cgroup-driver=systemd --cgroups-per-qos=true --client-ca-file=/etc/kubernetes/certs/ca.crt --cluster-dns=${DNS_IP} --cluster-domain=cluster.local --enforce-node-allocatable=pods --event-qps=0 --eviction-hard=memory.available<750Mi,nodefs.available<10%,nodefs.inodesFree<5%  --image-gc-high-threshold=65 --image-gc-low-threshold=55 --kube-reserved=cpu=180m,memory=2399Mi,pid=1000 --kubeconfig=/var/lib/kubelet/kubeconfig --max-pods=110 --node-status-update-frequency=10s --pod-infra-container-image=mcr.microsoft.com/oss/kubernetes/pause:3.6 --protect-kernel-defaults=true --read-only-port=0 --eviction-hard=memory.available<750Mi,nodefs.available<10%,nodefs.inodesFree<5%,pid.available<2000 --streaming-connection-idle-timeout=4h --tls-cert-file=/etc/kubernetes/certs/kubeletserver.crt --tls-cipher-suites=TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_256_GCM_SHA384,TLS_RSA_WITH_AES_128_GCM_SHA256 --tls-private-key-file=/etc/kubernetes/certs/kubeletserver.key --image-credential-provider-config=/opt/image-cred-provider/config/workload-identity-token.yaml --image-credential-provider-bin-dir=/opt/image-cred-provider/bin --container-log-max-size=5Gi --container-log-max-files=2 --plugin-watcher-timeout=30s"
EOF

# can simplify this + 2 following files by merging together
tee /etc/systemd/system/kubelet.service.d/10-containerd.conf > /dev/null <<'EOF'
[Service]
Environment=KUBELET_CONTAINERD_FLAGS="--runtime-request-timeout=15m --container-runtime-endpoint=unix:///run/containerd/containerd.sock"
EOF

tee /etc/systemd/system/kubelet.service.d/10-tlsbootstrap.conf > /dev/null <<'EOF'
[Service]
Environment=KUBELET_TLS_BOOTSTRAP_FLAGS="--kubeconfig /var/lib/kubelet/kubeconfig --bootstrap-kubeconfig /var/lib/kubelet/bootstrap-kubeconfig"
EOF

tee /etc/systemd/system/kubelet.service > /dev/null <<'EOF'
[Unit]
Description=Kubelet
ConditionPathExists=/usr/local/bin/kubelet
[Service]
Restart=always
RestartSec=5
StartLimitInterval=0
EnvironmentFile=/etc/default/kubelet
SuccessExitStatus=143
# Watchdog for early detection of kubelet issues
WatchdogSec=60
# Clean up plugin sockets on restart to prevent state corruption
ExecStartPre=/bin/bash -c "rm -f /var/lib/kubelet/plugins/dra-secondarynic/plugin.sock /var/lib/kubelet/plugins_registry/dra-secondarynic-reg.sock"
# Ace does not recall why this is done
ExecStartPre=/bin/bash -c "if [ $(mount | grep \"/var/lib/kubelet\" | wc -l) -le 0 ] ; then /bin/mount --bind /var/lib/kubelet /var/lib/kubelet ; fi"
ExecStartPre=/bin/mount --make-shared /var/lib/kubelet
ExecStartPre=-/sbin/ebtables -t nat --list
ExecStartPre=-/sbin/iptables -t nat --numeric --list
ExecStart=/usr/local/bin/kubelet \
        --enable-server \
        --node-labels="${KUBELET_NODE_LABELS}" \
        --v=2 \
        --volume-plugin-dir=/etc/kubernetes/volumeplugins \
        $KUBELET_TLS_BOOTSTRAP_FLAGS \
        $KUBELET_CONFIG_FILE_FLAGS \
        $KUBELET_CONTAINERD_FLAGS \
        $KUBELET_FLAGS
[Install]
WantedBy=multi-user.target
EOF

tee /var/lib/kubelet/bootstrap-kubeconfig > /dev/null <<EOF
apiVersion: v1
kind: Config
clusters:
- name: localcluster
  cluster:
    certificate-authority: /etc/kubernetes/certs/ca.crt
    server: "https://$AKS_FQDN"
users:
- name: kubelet-bootstrap
  user:
    exec:
      apiVersion: client.authentication.k8s.io/v1beta1
      args:
      - get-token
      - --environment
      - AzurePublicCloud
      - --server-id
      - 6dae42f8-4368-4678-94ff-3960e28e3630
      - --login
      - msi
      - --client-id
      - $BOOTSTRAP_CLIENT_ID
      command: kubelogin
      provideClusterInfo: false
contexts:
- context:
    cluster: localcluster
    user: kubelet-bootstrap
  name: bootstrap-context
current-context: bootstrap-context
EOF

AZURE_JSON_PATH="/etc/kubernetes/certs/ca.crt"
touch "${AZURE_JSON_PATH}"
chmod 0600 "${AZURE_JSON_PATH}"
chown root:root "${AZURE_JSON_PATH}"
echo $KUBE_CA_CERT | base64 -d > /etc/kubernetes/certs/ca.crt

AZURE_JSON_PATH="/etc/kubernetes/azure.json"
touch "${AZURE_JSON_PATH}"
chmod 0600 "${AZURE_JSON_PATH}"
chown root:root "${AZURE_JSON_PATH}"

KUBELET_SERVER_PRIVATE_KEY_PATH="/etc/kubernetes/certs/kubeletserver.key"
KUBELET_SERVER_CERT_PATH="/etc/kubernetes/certs/kubeletserver.crt"
openssl genrsa -out $KUBELET_SERVER_PRIVATE_KEY_PATH 4096
openssl req -new -x509 -days 7300 -key $KUBELET_SERVER_PRIVATE_KEY_PATH -out $KUBELET_SERVER_CERT_PATH -subj "/CN=system:node:${NODE_NAME}"

sysctl --system
systemctl enable --now containerd
systemctl enable --now kubelet

systemctl restart containerd
sleep 5
systemctl restart kubelet

# Create kubelet DRA health monitor service
tee /etc/systemd/system/kubelet-dra-monitor.service > /dev/null <<'EOF'
[Unit]
Description=Kubelet DRA Health Monitor
After=kubelet.service
Wants=kubelet.service

[Service]
Type=simple
ExecStart=/usr/local/bin/kubelet-dra-monitor.sh
Restart=always
RestartSec=30
User=root

[Install]
WantedBy=multi-user.target
EOF

# Create the monitoring script
tee /usr/local/bin/kubelet-dra-monitor.sh > /dev/null <<'EOF'
#!/bin/bash

STUCK_THRESHOLD=300  # 5 minutes
CHECK_INTERVAL=60    # 1 minute
LOG_PREFIX="[KubeletDRAMonitor]"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_PREFIX $1" | systemd-cat -p info -t kubelet-dra-monitor
}

check_stuck_pods() {
    # Check for pods stuck in ContainerCreating with DRA resource claims
    STUCK_PODS=$(kubectl get pods --all-namespaces --field-selector=status.phase=Pending -o json 2>/dev/null | \
        jq -r '.items[] | select(.status.conditions[]? | select(.type=="PodScheduled" and .status=="True")) | 
               select(.spec.resourceClaims != null) | 
               select((.status.containerStatuses[]? // empty) | select(.state.waiting.reason=="ContainerCreating")) |
               "\(.metadata.namespace)/\(.metadata.name):\(.metadata.creationTimestamp)"' 2>/dev/null)
    
    if [ -n "$STUCK_PODS" ]; then
        while IFS= read -r pod_info; do
            pod_name=$(echo "$pod_info" | cut -d':' -f1)
            creation_time=$(echo "$pod_info" | cut -d':' -f2)
            
            # Calculate age in seconds
            if command -v date >/dev/null 2>&1; then
                creation_epoch=$(date -d "$creation_time" +%s 2>/dev/null)
                current_epoch=$(date +%s)
                age=$((current_epoch - creation_epoch))
                
                if [ $age -gt $STUCK_THRESHOLD ]; then
                    log "Detected stuck pod: $pod_name (age: ${age}s, threshold: ${STUCK_THRESHOLD}s)"
                    
                    # Check if this is a DRA-related stuck pod
                    if kubectl describe pod "$pod_name" 2>/dev/null | grep -q "Failed to prepare dynamic resources"; then
                        log "Pod $pod_name stuck due to DRA issues - triggering kubelet restart"
                        systemctl restart kubelet
                        sleep 30  # Wait for restart
                        return
                    fi
                fi
            fi
        done <<< "$STUCK_PODS"
    fi
}

log "Starting kubelet DRA health monitor"

while true; do
    check_stuck_pods
    sleep $CHECK_INTERVAL
done
EOF

chmod +x /usr/local/bin/kubelet-dra-monitor.sh
systemctl enable kubelet-dra-monitor.service
systemctl start kubelet-dra-monitor.service

# sanity check? might be uninitialized at this point
# timeout 30s grep -q 'NodeReady' <(journalctl -u kubelet -f --no-tail)

exit 0