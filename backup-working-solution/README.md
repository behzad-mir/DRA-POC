# Working NRI + DRA Solution Backup

## Date Created: October 16, 2025

## Solution Overview
This backup contains a fully functional NRI (Node Resource Interface) + DRA (Dynamic Resource Allocation) architecture for moving secondary network interfaces (eth1) from Azure BYON nodes to Kubernetes pods with working connectivity.

## Architecture Components

### 1. NRI Plugin (`nri/`)
- **File**: `nri-plugin-grpc-client.go`
- **Purpose**: Detects test pods and moves eth1 interfaces using ip command approach
- **Key Features**:
  - gRPC client connecting to DRA driver on port 50051
  - Uses `/sbin/ip` commands (matching user's working manual method)
  - Handles network namespace detection and interface movement
  - File logging to `/tmp/nri-grpc-nic-hook.log`

### 2. DRA Driver (`main/`)
- **File**: `driver.go`
- **Purpose**: Provides static IP mapping based on node names
- **Key Features**:
  - gRPC server on port 50051
  - Static IP mapping:
    - myvm000000 → 10.9.255.4/24
    - myvm000001 → 10.9.255.5/24
  - Only allocates resources, NRI plugin handles interface movement

### 3. gRPC Protocol (`draProtos/`)
- **File**: `dra.proto`
- **Purpose**: Communication protocol between NRI plugin and DRA driver
- **Key Method**: `ConfigureNetwork` with networkNamespacePath field

## Key Success Factors

### 1. Static IP Mapping
The solution uses static IP addresses that were originally assigned by Azure to the eth1 interfaces:
- These specific IPs (10.9.255.4 and 10.9.255.5) are the only ones that work for connectivity
- Azure networking infrastructure only allows traffic from these pre-registered IP addresses

### 2. IP Command Approach
Uses exact same commands as user's working manual method:
```bash
/sbin/ip link set eth1 netns <namespace-name>
/sbin/ip netns exec <namespace-name> /sbin/ip addr add <ip> dev eth1
```

### 3. Azure BYON Configuration
- IP forwarding enabled on eth1 interfaces
- Network Security Groups allowing internal subnet communication
- Proper subnet configuration (nodenet2: 10.9.255.0/24)

## Deployment Files
- `test-nri-pod.yaml`: Test pod configuration with DRA resource claims
- `test-nri-pod-node2.yaml`: Test pod forced to specific node
- `resourceClaimTEmplate.yaml`: DRA resource claim template
- `deviceClass.yaml`: DRA device class definition

## Proven Connectivity
✅ Bidirectional ping connectivity between pods:
- Pod on myvm000000 (10.9.255.4) ↔ Pod on myvm000001 (10.9.255.5)
- 0% packet loss, ~1ms latency

## Build and Deploy Commands
```bash
# Build NRI plugin
cd nri/
go build -o nri-plugin-grpc-client nri-plugin-grpc-client.go

# Build and deploy DRA driver
cd main/
./imageBuild.sh
kubectl rollout restart daemonset/drasecondarynic -n kube-system

# Test deployment
kubectl apply -f test-nri-pod.yaml
kubectl apply -f test-nri-pod-node2.yaml
```

## Critical Insights
1. **Azure networking constraints**: Only original Azure-assigned IPs work
2. **Static mapping required**: Dynamic IP allocation fails due to Azure restrictions
3. **Node name detection**: DRA driver correctly identifies node names via NODE_NAME env var
4. **IP forwarding**: Essential for Azure to allow interface movement
5. **Exact command matching**: Using same ip commands as manual method is crucial

This solution represents a fully functional proof-of-concept for NRI-based network interface injection in Azure BYON environments.