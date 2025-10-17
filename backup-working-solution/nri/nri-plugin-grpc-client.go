package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "nri-nic-hook/draProtos"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
)

type nriGrpcPlugin struct {
	cfg       sync.Map // map[sandboxID]params
	draClient pb.NodeClient
	grpcConn  *grpc.ClientConn
}

type params struct {
	NICName string
	IP      string
	GW      string
	DNS     string
}

func (p *nriGrpcPlugin) name() string {
	return "nri-grpc-nic-hook"
}

func (p *nriGrpcPlugin) Configure(ctx context.Context, config, runtime, version string) (stub.EventMask, error) {
	log.Printf("[%s] Configure called: config=%s, runtime=%s, version=%s", p.name(), config, runtime, version)

	// Connect to DRA driver gRPC service
	draAddress := "localhost:50051" // Default DRA driver gRPC address
	if addr := os.Getenv("DRA_GRPC_ADDRESS"); addr != "" {
		draAddress = addr
	}

	log.Printf("[%s] Connecting to DRA driver at %s", p.name(), draAddress)

	conn, err := grpc.Dial(draAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Printf("[%s] Failed to connect to DRA driver: %v", p.name(), err)
		return 0, fmt.Errorf("failed to connect to DRA driver: %v", err)
	}

	p.grpcConn = conn
	p.draClient = pb.NewNodeClient(conn)

	log.Printf("[%s] Successfully connected to DRA driver", p.name())

	return api.EventMask(api.Event_RUN_POD_SANDBOX), nil
}

func (p *nriGrpcPlugin) Synchronize(ctx context.Context, pods []*api.PodSandbox, containers []*api.Container) ([]*api.ContainerUpdate, error) {
	log.Printf("[%s] Synchronize called", p.name())
	return nil, nil
}

// Wire the NIC into the pod's network namespace (based on your working version)
func (p *nriGrpcPlugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Printf("[%s] RunPodSandbox called for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())

	// Check if this pod should get network configuration
	if !p.shouldConfigureNetwork(pod) {
		log.Printf("[%s] Skipping pod %s/%s (no NIC requested)", p.name(), pod.GetNamespace(), pod.GetName())
		return nil
	}

	log.Printf("[%s] Pod %s/%s needs network configuration - getting config from DRA driver", p.name(), pod.GetNamespace(), pod.GetName())

	// Get network configuration from DRA driver via gRPC
	networkConfig, err := p.getNetworkConfigFromDRA(pod)
	if err != nil {
		log.Printf("[%s] Failed to get network config from DRA driver: %v", p.name(), err)
		return fmt.Errorf("failed to get network config: %v", err)
	}

	// Skip if no NIC config was returned
	if networkConfig.NICName == "" {
		log.Printf("[%s] Skipping pod %s/%s (no NIC config returned)", p.name(), pod.GetNamespace(), pod.GetName())
		return nil
	}

	linux := pod.GetLinux()
	if linux == nil {
		return fmt.Errorf("Linux sandbox required for NIC injection")
	}

	var netnsPath string
	for _, ns := range linux.Namespaces {
		if strings.EqualFold(ns.GetType(), "NETWORK") {
			netnsPath = ns.GetPath()
			break
		}
	}

	// Skip if no network namespace (hostNetwork or sandbox issue)
	if netnsPath == "" {
		log.Printf("[%s] Skipping pod %s/%s (hostNetwork or no netns)", p.name(), pod.GetNamespace(), pod.GetName())
		return nil
	}

	log.Printf("[%s] DRA driver returned network config for pod %s/%s: NIC=%s, IP=%s, GW=%s",
		p.name(), pod.GetNamespace(), pod.GetName(), networkConfig.NICName, networkConfig.IP, networkConfig.GW)

	// Now perform the actual network interface movement using proper namespace handling
	if err := p.configureNetworkInterface(networkConfig, netnsPath); err != nil {
		log.Printf("[%s] Failed to configure network interface for pod %s/%s: %v", p.name(), pod.GetNamespace(), pod.GetName(), err)
		return fmt.Errorf("failed to configure network interface: %v", err)
	}

	log.Printf("[%s] Network configuration completed successfully for pod %s/%s",
		p.name(), pod.GetNamespace(), pod.GetName())
	return nil
}

// configureNetworkInterface moves the network interface to the pod's network namespace
// using the same approach as the working manual commands (ip link set netns approach)
func (p *nriGrpcPlugin) configureNetworkInterface(config params, nsPath string) error {
	log.Printf("[%s] Moving interface %s to namespace %s using ip command approach", p.name(), config.NICName, nsPath)

	// Extract namespace name from the path (e.g., "/var/run/netns/cni-xxx" -> "cni-xxx")
	nsName := ""
	if strings.HasPrefix(nsPath, "/var/run/netns/") {
		nsName = strings.TrimPrefix(nsPath, "/var/run/netns/")
	} else {
		return fmt.Errorf("unexpected namespace path format: %s", nsPath)
	}

	log.Printf("[%s] Using namespace name: %s (extracted from path: %s)", p.name(), nsName, nsPath)

	// Move interface using ip command (same as working manual approach)
	if err := p.moveInterfaceWithIPCommand(config.NICName, nsName); err != nil {
		return fmt.Errorf("failed to move interface %s to namespace %s: %v", config.NICName, nsName, err)
	}

	log.Printf("[%s] Successfully moved interface %s to namespace %s", p.name(), config.NICName, nsName)

	// Configure IP address using ip command (same as working manual approach)
	if config.IP != "" {
		if err := p.configureIPWithIPCommand(nsName, config.NICName, config.IP); err != nil {
			return fmt.Errorf("failed to configure IP %s on interface %s: %v", config.IP, config.NICName, err)
		}
		log.Printf("[%s] Successfully configured IP %s on interface %s", p.name(), config.IP, config.NICName)
	}

	return nil
}

// moveInterfaceWithIPCommand moves interface using ip command (same as working manual approach)
func (p *nriGrpcPlugin) moveInterfaceWithIPCommand(ifName, nsName string) error {
	log.Printf("[%s] Executing: /sbin/ip link set %s netns %s", p.name(), ifName, nsName)

	cmd := exec.Command("/sbin/ip", "link", "set", ifName, "netns", nsName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set command failed: %v, output: %s", err, string(output))
	}

	log.Printf("[%s] Successfully moved interface %s to namespace %s", p.name(), ifName, nsName)
	return nil
}

// configureIPWithIPCommand configures IP using ip command (same as working manual approach)
func (p *nriGrpcPlugin) configureIPWithIPCommand(nsName, ifName, ipAddr string) error {
	// Add IP address to interface
	log.Printf("[%s] Executing: /sbin/ip netns exec %s /sbin/ip addr add %s dev %s", p.name(), nsName, ipAddr, ifName)

	cmd := exec.Command("/sbin/ip", "netns", "exec", nsName, "/sbin/ip", "addr", "add", ipAddr, "dev", ifName)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Check if the address already exists
		if strings.Contains(string(output), "File exists") {
			log.Printf("[%s] IP address %s already exists on interface %s", p.name(), ipAddr, ifName)
		} else {
			return fmt.Errorf("ip addr add command failed: %v, output: %s", err, string(output))
		}
	}

	// Bring interface up
	log.Printf("[%s] Executing: /sbin/ip netns exec %s /sbin/ip link set %s up", p.name(), nsName, ifName)

	cmd = exec.Command("/sbin/ip", "netns", "exec", nsName, "/sbin/ip", "link", "set", ifName, "up")
	output, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip link set up command failed: %v, output: %s", err, string(output))
	}

	log.Printf("[%s] Successfully configured and brought up interface %s with IP %s", p.name(), ifName, ipAddr)
	return nil
}

func (p *nriGrpcPlugin) getNetworkConfigFromDRA(pod *api.PodSandbox) (params, error) {
	log.Printf("[%s] Getting network config from DRA driver for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())

	// Extract resource claims from pod
	resourceClaims := p.extractResourceClaims(pod)

	// Extract the Kubernetes pod UID from pod metadata
	kubernetesUID := pod.GetUid()
	if kubernetesUID == "" {
		kubernetesUID = p.extractKubernetesPodUID(pod)
	}

	// Extract network namespace path from pod Linux spec
	networkNamespacePath := ""
	networkNamespaceName := ""
	if pod.GetLinux() != nil {
		for _, ns := range pod.GetLinux().GetNamespaces() {
			if strings.EqualFold(ns.GetType(), "NETWORK") && ns.GetPath() != "" {
				networkNamespacePath = ns.GetPath()
				// Extract just the namespace name from the full path
				// e.g., "/var/run/netns/cni-54fe9b7d-1b6e-09c0-5651-1bfb4d5325f9" -> "cni-54fe9b7d-1b6e-09c0-5651-1bfb4d5325f9"
				if strings.HasPrefix(networkNamespacePath, "/var/run/netns/") {
					networkNamespaceName = strings.TrimPrefix(networkNamespacePath, "/var/run/netns/")
				} else {
					networkNamespaceName = networkNamespacePath // fallback to full path if not standard format
				}
				break
			}
		}
	}
	log.Printf("[%s] Network namespace path: %s, name: %s", p.name(), networkNamespacePath, networkNamespaceName)

	// Call DRA driver to get network configuration
	req := &pb.ConfigureNetworkRequest{
		PodNamespace:         pod.GetNamespace(),
		PodName:              pod.GetName(),
		ContainerName:        "", // Not available in RunPodSandbox
		ContainerPid:         0,  // Not available in RunPodSandbox
		PodUID:               kubernetesUID,
		ResourceClaims:       resourceClaims,
		NetworkNamespacePath: networkNamespacePath, // Send full path, let DRA driver handle the conversion
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("[%s] Calling DRA driver to get network config for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())
	resp, err := p.draClient.ConfigureNetwork(ctx, req)
	if err != nil {
		return params{}, fmt.Errorf("DRA driver gRPC failed: %v", err)
	}

	if !resp.GetSuccess() {
		return params{}, fmt.Errorf("DRA driver network configuration failed: %s", resp.GetErrorMessage())
	}

	// Extract the network configuration
	if len(resp.GetInterfaces()) > 0 {
		iface := resp.GetInterfaces()[0] // Take first interface
		nc := params{
			NICName: iface.GetNicName(),
			IP:      iface.GetIpAddress(),
			GW:      iface.GetGateway(),
			DNS:     "", // DNS not available from current interface
		}
		log.Printf("[%s] Got network config from DRA: NIC=%s, IP=%s, GW=%s",
			p.name(), nc.NICName, nc.IP, nc.GW)
		return nc, nil
	}

	return params{}, fmt.Errorf("no network interface configuration returned by DRA driver")
}

func (p *nriGrpcPlugin) shouldConfigureNetwork(pod *api.PodSandbox) bool {
	// Check annotations for DRA resource claims
	annotations := pod.GetAnnotations()
	for key := range annotations {
		if key == "resource.k8s.io/claim-name" || key == "network.dra/claim" {
			log.Printf("[%s] Found DRA resource claim annotation: %s", p.name(), key)
			return true
		}
	}

	// Check labels for test pods
	labels := pod.GetLabels()
	if appLabel, exists := labels["app"]; exists {
		if appLabel == "test-nri-interface" || appLabel == "test-nri-interface-node2" {
			log.Printf("[%s] Found test pod label: %s", p.name(), appLabel)
			return true
		}
	}

	// Check pod name patterns
	podName := pod.GetName()
	if podName == "test-nri-interface" || podName == "test-nri-interface-node2" {
		log.Printf("[%s] Found test pod name: %s", p.name(), podName)
		return true
	}

	return false
}

func (p *nriGrpcPlugin) extractResourceClaims(pod *api.PodSandbox) []*pb.ResourceClaim {
	resourceClaims := []*pb.ResourceClaim{}

	// Extract from annotations
	annotations := pod.GetAnnotations()
	for key, value := range annotations {
		if key == "resource.k8s.io/claim-name" || key == "network.dra/claim" {
			resourceClaims = append(resourceClaims, &pb.ResourceClaim{
				Name: value,
				Uid:  pod.GetId(),
			})
			log.Printf("[%s] Added resource claim from annotation: %s", p.name(), value)
		}
	}

	// For test pods, add synthetic resource claims
	labels := pod.GetLabels()
	if appLabel, exists := labels["app"]; exists {
		if appLabel == "test-nri-interface" || appLabel == "test-nri-interface-node2" {
			resourceClaims = append(resourceClaims, &pb.ResourceClaim{
				Name: "secondary-nic",
				Uid:  pod.GetId(),
			})
			log.Printf("[%s] Added synthetic resource claim for test pod", p.name())
		}
	}

	podName := pod.GetName()
	if podName == "test-nri-interface" || podName == "test-nri-interface-node2" {
		if len(resourceClaims) == 0 { // Only add if not already added
			resourceClaims = append(resourceClaims, &pb.ResourceClaim{
				Name: "secondary-nic",
				Uid:  pod.GetId(),
			})
			log.Printf("[%s] Added synthetic resource claim for test pod name", p.name())
		}
	}

	return resourceClaims
}

func (p *nriGrpcPlugin) findContainerPID(podUID string) int {
	// Try to find container PID by looking up running containers
	// This is a simple approach - in production you might want to use container runtime APIs
	log.Printf("[%s] Looking for container PID for pod UID: %s", p.name(), podUID)

	// For now, return 0 to indicate PID not found
	// The DRA driver will need to handle this case
	return 0
}

func (p *nriGrpcPlugin) extractKubernetesPodUID(pod *api.PodSandbox) string {
	// The actual Kubernetes pod UID needs to be extracted from pod metadata
	// Let's check all available metadata first
	annotations := pod.GetAnnotations()
	labels := pod.GetLabels()

	log.Printf("[%s] Debug - All pod annotations: %+v", p.name(), annotations)
	log.Printf("[%s] Debug - All pod labels: %+v", p.name(), labels)

	// Check for common Kubernetes UID annotations
	if uid, exists := annotations["io.kubernetes.pod.uid"]; exists {
		log.Printf("[%s] Found K8s pod UID in annotations: %s", p.name(), uid)
		return uid
	}

	// Check for UID in other common annotation keys
	uidKeys := []string{
		"kubernetes.io/pod.uid",
		"k8s.v1.cni.cncf.io/pod-uid",
		"pod.uid",
	}

	for _, key := range uidKeys {
		if uid, exists := annotations[key]; exists {
			log.Printf("[%s] Found K8s pod UID in annotation %s: %s", p.name(), key, uid)
			return uid
		}
	}

	// As fallback, return a placeholder that indicates we need the real UID
	// The DRA driver will need to handle finding the correct namespace
	log.Printf("[%s] WARNING: Could not find Kubernetes pod UID in metadata", p.name())
	log.Printf("[%s] NRI sandbox ID: %s", p.name(), pod.GetId())

	// Return the sandbox ID as fallback but log that it might not work
	return pod.GetId()
}

func (p *nriGrpcPlugin) RemovePodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Printf("[%s] RemovePodSandbox called for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *nriGrpcPlugin) StopPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Printf("[%s] StopPodSandbox called for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())
	return nil
}

func (p *nriGrpcPlugin) Shutdown(ctx context.Context) {
	log.Printf("[%s] Shutdown called", p.name())
	if p.grpcConn != nil {
		p.grpcConn.Close()
		log.Printf("[%s] Closed gRPC connection to DRA driver", p.name())
	}
}

func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	return buf.String(), err
}

func main() {
	logFile, err := os.OpenFile("/tmp/nri-grpc-nic-hook.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Printf("=== NRI gRPC Plugin Starting ===")
	log.Printf("Plugin name: %s", "nri-grpc-nic-hook")

	plugin := &nriGrpcPlugin{}
	log.Printf("Created plugin struct")

	s, err := stub.New(plugin)
	if err != nil {
		log.Fatalf("failed to create stub: %v", err)
	}
	log.Printf("Created NRI stub successfully")

	log.Printf("Starting plugin registration and run...")
	if err := s.Run(context.Background()); err != nil {
		log.Fatalf("stub run failed: %v", err)
	}
}
