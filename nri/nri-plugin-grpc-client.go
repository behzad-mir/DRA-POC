package main

import (
	"context"
	"fmt"
	"log"
	"os"
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

// THIN NRI PLUGIN: Only calls DRA driver - no direct network manipulation
func (p *nriGrpcPlugin) RunPodSandbox(ctx context.Context, pod *api.PodSandbox) error {
	log.Printf("[%s] RunPodSandbox called for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())

	// Check if this pod should get network configuration
	if !p.shouldConfigureNetwork(pod) {
		log.Printf("[%s] Skipping pod %s/%s (no NIC requested)", p.name(), pod.GetNamespace(), pod.GetName())
		return nil
	}

	log.Printf("[%s] Pod %s/%s needs network configuration - delegating to DRA driver", p.name(), pod.GetNamespace(), pod.GetName())

	// Get network configuration from DRA driver via gRPC (DRA driver handles everything)
	err := p.callDRADriverOnly(pod)
	if err != nil {
		log.Printf("[%s] Failed to call DRA driver: %v", p.name(), err)
		return fmt.Errorf("failed to call DRA driver: %v", err)
	}

	log.Printf("[%s] DRA driver completed network configuration for pod %s/%s",
		p.name(), pod.GetNamespace(), pod.GetName())
	return nil
}

// callDRADriverOnly - thin plugin only calls DRA driver, does no network operations itself
func (p *nriGrpcPlugin) callDRADriverOnly(pod *api.PodSandbox) error {
	log.Printf("[%s] Calling DRA driver for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())

	// Extract resource claims from pod
	resourceClaims := p.extractResourceClaims(pod)

	// Extract the Kubernetes pod UID from pod metadata
	kubernetesUID := pod.GetUid()
	if kubernetesUID == "" {
		kubernetesUID = p.extractKubernetesPodUID(pod)
	}

	// Extract network namespace path from pod Linux spec
	networkNamespacePath := ""
	if pod.GetLinux() != nil {
		for _, ns := range pod.GetLinux().GetNamespaces() {
			if strings.EqualFold(ns.GetType(), "NETWORK") && ns.GetPath() != "" {
				networkNamespacePath = ns.GetPath()
				break
			}
		}
	}
	log.Printf("[%s] Network namespace path: %s", p.name(), networkNamespacePath)

	// Call DRA driver - DRA driver handles ALL network interface operations
	req := &pb.ConfigureNetworkRequest{
		PodNamespace:         pod.GetNamespace(),
		PodName:              pod.GetName(),
		ContainerName:        "", // Not available in RunPodSandbox
		ContainerPid:         0,  // Not available in RunPodSandbox
		PodUID:               kubernetesUID,
		ResourceClaims:       resourceClaims,
		NetworkNamespacePath: networkNamespacePath,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	log.Printf("[%s] Calling DRA driver to handle network configuration for pod %s/%s", p.name(), pod.GetNamespace(), pod.GetName())
	resp, err := p.draClient.ConfigureNetwork(ctx, req)
	if err != nil {
		return fmt.Errorf("DRA driver gRPC failed: %v", err)
	}

	if !resp.GetSuccess() {
		return fmt.Errorf("DRA driver network configuration failed: %s", resp.GetErrorMessage())
	}

	log.Printf("[%s] DRA driver successfully configured %d interfaces for pod %s",
		p.name(), len(resp.GetInterfaces()), pod.GetName())
	return nil
}

func (p *nriGrpcPlugin) shouldConfigureNetwork(pod *api.PodSandbox) bool {
	// Primary detection: Check for resource claims that indicate DRA network interfaces
	resourceClaims := p.extractResourceClaims(pod)
	if len(resourceClaims) > 0 {
		log.Printf("[%s] Found %d resource claims, processing pod %s/%s", p.name(), len(resourceClaims), pod.GetNamespace(), pod.GetName())
		return true
	}

	// Secondary detection: Check for network-related DRA annotations
	annotations := pod.GetAnnotations()
	for key, value := range annotations {
		if strings.Contains(key, "resource.k8s.io") && strings.Contains(value, "nic") {
			log.Printf("[%s] Found DRA resource annotation %s=%s", p.name(), key, value)
			return true
		}
	}

	// Tertiary detection: Check for DRA-related labels
	labels := pod.GetLabels()
	if labels["network.dra.k8s.io/enabled"] == "true" {
		log.Printf("[%s] Found DRA network label", p.name())
		return true
	}

	// Fallback: Support existing test pods during transition period
	if appLabel, exists := labels["app"]; exists {
		if appLabel == "test-nri-interface" || appLabel == "test-nri-interface-node2" || appLabel == "relay-app" {
			log.Printf("[%s] Found test pod label: %s (fallback detection)", p.name(), appLabel)
			return true
		}
	}

	podName := pod.GetName()
	if strings.HasPrefix(podName, "test-nri-interface") {
		log.Printf("[%s] Found test pod name: %s (fallback detection)", p.name(), podName)
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
		if appLabel == "test-nri-interface" || appLabel == "test-nri-interface-node2" || appLabel == "relay-app" {
			resourceClaims = append(resourceClaims, &pb.ResourceClaim{
				Name: "secondary-nic",
				Uid:  pod.GetId(),
			})
			log.Printf("[%s] Added synthetic resource claim for test pod", p.name())
		}
	}

	podName := pod.GetName()
	if strings.HasPrefix(podName, "test-nri-interface") {
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

func (p *nriGrpcPlugin) extractKubernetesPodUID(pod *api.PodSandbox) string {
	// The actual Kubernetes pod UID needs to be extracted from pod metadata
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

	// As fallback, return the sandbox ID
	log.Printf("[%s] WARNING: Could not find Kubernetes pod UID in metadata", p.name())
	log.Printf("[%s] NRI sandbox ID: %s", p.name(), pod.GetId())

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

func main() {
	logFile, err := os.OpenFile("/tmp/nri-grpc-nic-hook.log", os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		log.Fatalf("Failed to open log file: %v", err)
	}
	defer logFile.Close()
	log.SetOutput(logFile)

	log.Printf("=== THIN NRI gRPC Plugin Starting ===")
	log.Printf("Architecture: Thin NRI plugin delegates ALL network operations to DRA driver")
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
