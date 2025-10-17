// SPDX-License-Identifier: MIT
// DRA node driver for Kubernetes v1.33.x using the upstream kubeletplugin helper.
// - Registers as a DRAPlugin named "dra-secondarynic"
// - Listens at /var/lib/kubelet/plugins/dra-secondarynic/plugin.sock
// - Publishes (optional) resources; keeps your NIC/CDI preparation logic

package main

import (
	"context"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"

	pb "example.com/dra-secondarynic/draProtos"
	"google.golang.org/grpc"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
)

const (
	DriverName             = "dra-secondarynic" // MUST match DeviceClass/ResourceSlice .spec.driver
	PluginRegistrationPath = "/var/lib/kubelet/plugins_registry/" + DriverName + ".sock"
	DriverPluginPath       = "/var/lib/kubelet/plugins/" + DriverName
	DriverPluginSocketPath = DriverPluginPath + "/plugin.sock"
)

func main() {
	// Basic logging
	klog.InitFlags(nil)

	// Ensure plugin directory exists
	if err := os.MkdirAll(DriverPluginPath, 0o755); err != nil {
		klog.Fatalf("create plugin dir: %v", err)
	}

	// Discover node name (required by helper)
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		hostname, _ := os.Hostname()
		nodeName = hostname
	}

	// Required: in-cluster Kubernetes client for DRA operations
	cs, err := NewClientSets()
	if err != nil {
		klog.Fatalf("failed to create Kubernetes client: %v", err)
	}

	// Build the DRA driver implementation (keeps your NIC/CDI logic)
	drv := NewDriver( /* optional pool, e.g. []string{"eth1"} */ nil, nodeName, DriverName)

	// Start additional gRPC server for NRI plugin communication
	grpcPort := "50051"
	if port := os.Getenv("DRA_GRPC_PORT"); port != "" {
		grpcPort = port
	}

	lis, err := net.Listen("tcp", ":"+grpcPort)
	if err != nil {
		klog.Fatalf("failed to listen on gRPC port %s: %v", grpcPort, err)
	}

	grpcServer := grpc.NewServer()
	pb.RegisterNodeServer(grpcServer, drv)

	// Start gRPC server in background
	go func() {
		log.Printf("[DRASecondaryNIC] Starting gRPC server on port %s for NRI communication", grpcPort)
		if err := grpcServer.Serve(lis); err != nil {
			klog.Errorf("gRPC server failed: %v", err)
		}
	}()

	// Start the helper: this sets up BOTH registration and the DRA gRPC server wiring.
	plugin, err := kubeletplugin.Start(
		context.Background(),
		drv,                               // your DRAPlugin implementation
		kubeletplugin.KubeClient(cs.Core), // Required Kubernetes client
		kubeletplugin.NodeName(nodeName),
		kubeletplugin.DriverName(DriverName),
		kubeletplugin.RegistrarDirectoryPath("/var/lib/kubelet/plugins_registry"), // watcher dials this
		kubeletplugin.PluginSocket("plugin.sock"),                                 /* your server binds here */
	)
	if err != nil {
		klog.Fatalf("start kubeletplugin: %v", err)
	}

	// Publish resources to advertise available NICs to Kubernetes scheduler
	ctx := context.Background()
	driverResources := drv.GetResourcesForSlice()

	if len(driverResources.Pools) > 0 {
		if err := plugin.PublishResources(ctx, driverResources); err != nil {
			klog.Errorf("failed to publish resources: %v", err)
		} else {
			klog.Infof("[DRASecondaryNIC] published network resource pools")
		}
	}

	klog.Infof("[DRASecondaryNIC] Driver %q up on node %q", DriverName, nodeName)
	// Graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	<-ctx.Done()
	plugin.Stop() // unregisters cleanly
	cancel()
	klog.Info("[DRASecondaryNIC] driver stopped")
}
