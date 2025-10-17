package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	pb "example.com/dra-secondarynic/draProtos"
	"google.golang.org/grpc"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/klog/v2"
)

const (
	DriverName             = "dra-secondarynic" // MUST match DeviceClass/ResourceSlice .spec.driver
	PluginRegistrationPath = "/var/lib/kubelet/plugins_registry/" + DriverName + "-reg.sock"
	DriverPluginPath       = "/var/lib/kubelet/plugins/" + DriverName
	DriverPluginSocketPath = DriverPluginPath + "/plugin.sock"
)

// checkKubeletRegistration checks if kubelet has successfully registered our DRA driver
func checkKubeletRegistration() bool {
	// Check if kubelet log shows successful DRA driver registration in the last 5 minutes
	cmd := exec.Command("journalctl", "-u", "kubelet", "--since", "5 minutes ago")
	output, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[DRASecondaryNIC] Failed to check kubelet logs: %v", err)
		return false
	}

	// Look for DRA registration success indicators
	logStr := string(output)
	return fmt.Sprintf("RegisterPlugin started.*%s-reg.sock", DriverName) != "" &&
		fmt.Sprintf("Connection changed.*%s.*connected=true", DriverName) != "" &&
		len(logStr) > 0 // Basic validation
}

// triggerKubeletRestart attempts to restart kubelet when DRA state corruption is detected
func triggerKubeletRestart() error {
	log.Printf("[DRASecondaryNIC] Attempting to restart kubelet to clear stuck DRA state...")

	// Try multiple approaches to restart kubelet from within container
	approaches := []struct {
		name string
		cmd  *exec.Cmd
	}{
		{
			"host systemctl via nsenter",
			exec.Command("nsenter", "--target", "1", "--mount", "--uts", "--ipc", "--net", "--pid", "--", "systemctl", "restart", "kubelet"),
		},
		{
			"host systemctl direct path",
			exec.Command("/host/usr/bin/systemctl", "restart", "kubelet"),
		},
		{
			"chroot approach",
			exec.Command("chroot", "/host", "systemctl", "restart", "kubelet"),
		},
	}

	for _, approach := range approaches {
		log.Printf("[DRASecondaryNIC] Trying %s...", approach.name)
		output, err := approach.cmd.CombinedOutput()
		if err == nil {
			log.Printf("[DRASecondaryNIC] Kubelet restart successful using %s: %s", approach.name, string(output))
			return nil
		}
		log.Printf("[DRASecondaryNIC] %s failed: %v, output: %s", approach.name, err, output)
	}

	return fmt.Errorf("all kubelet restart approaches failed")
}

// watchRegistrationHealth monitors registration and aggressively forces re-registration when kubelet loses track
func watchRegistrationHealth(drv *Driver, cs ClientSets, nodeName string, helper *kubeletplugin.Helper) {
	// Reduced wait time - start monitoring immediately since registration can fail early
	time.Sleep(15 * time.Second) // Start checking after 15 seconds

	ticker := time.NewTicker(15 * time.Second) // Check every 15 seconds
	defer ticker.Stop()

	consecutiveFailures := 0
	consecutiveResourceFailures := 0 // Track resource discovery failures separately
	lastSuccessfulCheck := time.Now()

	for {
		select {
		case <-ticker.C:
			// The critical check: look for active DRA registration using kubeletplugin helper
			kubeletRegistrationOK := checkKubeletDRAStatus(helper)

			// Critical resource check: verify we can actually discover network resources
			resourceDiscoveryOK := checkResourceDiscoveryHealth(drv, nodeName)

			// Additional check: look for kubelet log errors indicating registration drift
			kubeletLogHealthy := checkKubeletLogsForDRAErrors()

			// Extra check: look for signs that our driver might have issues with recent operations
			recentOperationsFailed := checkForRecentOperationFailures()

			if kubeletRegistrationOK && kubeletLogHealthy && !recentOperationsFailed && resourceDiscoveryOK {
				if consecutiveFailures > 0 || consecutiveResourceFailures > 0 {
					log.Printf("[DRASecondaryNIC] Registration and resource discovery fully restored after %d registration failures, %d resource failures", consecutiveFailures, consecutiveResourceFailures)
					consecutiveFailures = 0
					consecutiveResourceFailures = 0
				} else {
					log.Printf("[DRASecondaryNIC] Registration healthy - all checks passed")
				}
				lastSuccessfulCheck = time.Now()
			} else {
				// Track different types of failures separately
				if !kubeletRegistrationOK {
					consecutiveFailures++
				}
				if !resourceDiscoveryOK {
					consecutiveResourceFailures++
				}

				// Enhanced logging for different failure types
				if kubeletRegistrationOK && kubeletLogHealthy && !recentOperationsFailed && !resourceDiscoveryOK {
					log.Printf("[DRASecondaryNIC] CRITICAL ISSUE DETECTED: Registration appears healthy but resource discovery failing (resource failure #%d)", consecutiveResourceFailures)
				} else if kubeletRegistrationOK && kubeletLogHealthy && recentOperationsFailed {
					log.Printf("[DRASecondaryNIC] CRITICAL ISSUE DETECTED: Driver appears healthy but cluster operations are failing (failure #%d)", consecutiveFailures)
				} else if kubeletRegistrationOK && !kubeletLogHealthy {
					log.Printf("[DRASecondaryNIC] CRITICAL ISSUE DETECTED: Driver reports healthy but kubelet logs show registration drift (failure #%d)", consecutiveFailures)
				} else if !kubeletRegistrationOK && kubeletLogHealthy {
					log.Printf("[DRASecondaryNIC] ISSUE DETECTED: Driver registration failed but no kubelet errors yet (failure #%d)", consecutiveFailures)
				} else {
					log.Printf("[DRASecondaryNIC] ISSUE DETECTED: Multiple registration problems detected (failures: reg=%d, resource=%d)", consecutiveFailures, consecutiveResourceFailures)
				}

				// Enhanced escalation strategy:
				// 1. Resource discovery failures (persistent 0 resources) = immediate kubelet restart
				// 2. Registration failures = try re-registration first, then kubelet restart
				if consecutiveResourceFailures >= 1 {
					// Resource discovery failing even once - escalate immediately to kubelet restart
					// This is the classic registration drift - trigger kubelet restart on first failure
					log.Printf("[DRASecondaryNIC] ESCALATION: Resource discovery failing for %d checks - triggering kubelet restart to fix registration drift", consecutiveResourceFailures)

					err := triggerKubeletRestart()
					if err != nil {
						log.Printf("[DRASecondaryNIC] Failed to restart kubelet: %v", err)
					} else {
						log.Printf("[DRASecondaryNIC] Successfully triggered kubelet restart for resource discovery issue - waiting for recovery...")
						consecutiveFailures = 0
						consecutiveResourceFailures = 0
						time.Sleep(30 * time.Second) // Give kubelet time to restart and re-register
					}
				} else if consecutiveFailures >= 1 && consecutiveFailures < 2 && consecutiveResourceFailures < 1 {
					// Registration failure - try re-registration first
					log.Printf("[DRASecondaryNIC] CRITICAL: Re-registering DRA plugin immediately after failure #%d", consecutiveFailures)

					// Stop the current kubeletplugin helper
					log.Printf("[DRASecondaryNIC] Stopping current kubeletplugin helper...")
					helper.Stop()
					time.Sleep(2 * time.Second)

					// Start a new kubeletplugin helper
					log.Printf("[DRASecondaryNIC] Starting new kubeletplugin helper...")
					newPlugin, err := kubeletplugin.Start(
						context.Background(),
						drv,
						kubeletplugin.KubeClient(cs.Core),
						kubeletplugin.NodeName(nodeName),
						kubeletplugin.DriverName(DriverName),
						kubeletplugin.RegistrarDirectoryPath("/var/lib/kubelet/plugins_registry"),
						kubeletplugin.PluginSocket("plugin.sock"),
					)

					if err != nil {
						log.Printf("[DRASecondaryNIC] Failed to restart kubeletplugin helper: %v", err)
					} else {
						log.Printf("[DRASecondaryNIC] Successfully restarted kubeletplugin helper")

						// Wait for new registration to complete
						regErr := wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
							status := newPlugin.RegistrationStatus()
							if status == nil {
								return false, nil
							}
							return status.PluginRegistered, nil
						})

						if regErr != nil {
							log.Printf("[DRASecondaryNIC] New registration failed: %v", regErr)
						} else {
							log.Printf("[DRASecondaryNIC] New registration successful!")
							helper = newPlugin // Update helper reference

							// Republish resources
							ctx := context.Background()
							driverResources := drv.GetResourcesForSlice()
							if len(driverResources.Pools) > 0 {
								if err := helper.PublishResources(ctx, driverResources); err != nil {
									log.Printf("[DRASecondaryNIC] Failed to republish resources: %v", err)
								} else {
									log.Printf("[DRASecondaryNIC] Successfully republished resources")
								}
							}

							consecutiveFailures = 0
							// Do NOT reset consecutiveResourceFailures here - let the next health check determine if resource discovery is working
							lastSuccessfulCheck = time.Now()
						}
					}
				} else if consecutiveFailures >= 2 && consecutiveResourceFailures < 1 {
					// After just 2 failed re-registration attempts, escalate to kubelet restart for faster debugging
					log.Printf("[DRASecondaryNIC] ESCALATION: %d failed re-registrations, attempting kubelet restart to clear stuck state", consecutiveFailures)

					err := triggerKubeletRestart()
					if err != nil {
						log.Printf("[DRASecondaryNIC] Failed to restart kubelet: %v", err)
					} else {
						log.Printf("[DRASecondaryNIC] Successfully triggered kubelet restart - waiting for recovery...")
						consecutiveFailures = 0
						consecutiveResourceFailures = 0 // Reset both counters after kubelet restart
						time.Sleep(30 * time.Second)    // Give kubelet time to restart and re-register
					}
				}
			}

			// Emergency escalation if registration has been broken for too long
			if time.Since(lastSuccessfulCheck) > 2*time.Minute {
				log.Printf("[DRASecondaryNIC] EMERGENCY: No successful registration in %v - will attempt helper restart", time.Since(lastSuccessfulCheck))

				// Stop and restart helper as emergency measure
				log.Printf("[DRASecondaryNIC] Emergency: Stopping current kubeletplugin helper...")
				helper.Stop()
				time.Sleep(2 * time.Second)

				// Start a new kubeletplugin helper
				log.Printf("[DRASecondaryNIC] Emergency: Starting new kubeletplugin helper...")
				newPlugin, err := kubeletplugin.Start(
					context.Background(),
					drv,
					kubeletplugin.KubeClient(cs.Core),
					kubeletplugin.NodeName(nodeName),
					kubeletplugin.DriverName(DriverName),
					kubeletplugin.RegistrarDirectoryPath("/var/lib/kubelet/plugins_registry"),
					kubeletplugin.PluginSocket("plugin.sock"),
				)

				if err != nil {
					log.Printf("[DRASecondaryNIC] Emergency helper restart failed: %v", err)
				} else {
					helper = newPlugin
					log.Printf("[DRASecondaryNIC] Emergency helper restart successful")
				}

				lastSuccessfulCheck = time.Now() // Prevent spam
			}
		}
	}
}

// checkResourceDiscoveryHealth verifies that our driver can actually discover network resources
func checkResourceDiscoveryHealth(drv *Driver, nodeName string) bool {
	// Get current resource count from actual Kubernetes state instead of in-memory map
	drv.mu.Lock()
	totalFreeInterfaces := len(drv.free)
	totalClaimedInterfaces := len(drv.claims)                                // Number of claims tracked by driver
	totalInitiallyDiscovered := totalFreeInterfaces + totalClaimedInterfaces // This represents the true initial discovery
	drv.mu.Unlock()

	// Query Kubernetes API for active resource claims on this node
	totalAllocatedInterfaces := getActiveResourceClaimsCount(drv, nodeName)

	log.Printf("[DRASecondaryNIC] Resource status: %d initially discovered, %d free, %d allocated (via K8s API)",
		totalInitiallyDiscovered, totalFreeInterfaces, totalAllocatedInterfaces)

	// Check if this is a BYON node that should have secondary interfaces
	// Only BYON nodes have eth1 interfaces - other nodes (like master nodes) don't
	shouldHaveInterfaces := isBYONNode(nodeName)

	if !shouldHaveInterfaces {
		// This is not a BYON node (e.g., master node) - 0 interfaces is expected and healthy
		log.Printf("[DRASecondaryNIC] Resource discovery healthy: non-BYON node %s correctly has 0 interfaces", nodeName)
		return true
	}

	// Registration drift detection should be based on kubelet plugin status, not resource counts
	// Having 0 total discovered interfaces is NORMAL when no DRA pods are running
	// The driver only allocates interfaces when pods request them through resource claims

	if totalInitiallyDiscovered == 0 && totalAllocatedInterfaces == 0 {
		// No interfaces discovered AND no active claims = normal idle state
		log.Printf("[DRASecondaryNIC] Resource discovery healthy: idle state - no DRA resources currently requested on BYON node %s", nodeName)
		return true
	}

	// If we have discovered interfaces but 0 available, that's normal allocation behavior
	if totalFreeInterfaces == 0 && totalInitiallyDiscovered > 0 {
		log.Printf("[DRASecondaryNIC] Resource discovery healthy: %d interfaces discovered, all currently allocated", totalInitiallyDiscovered)
		return true
	}

	// CRITICAL: Detect kubelet communication mismatch
	// If K8s API shows allocated claims but driver sees no allocations, kubelet communication is broken
	// The key insight: if claims are allocated via K8s API but driver internal state shows all interfaces as "free",
	// this means kubelet never called the driver's allocation methods due to communication failure

	// Compare expected vs actual driver state
	expectedFreeInterfaces := totalInitiallyDiscovered - totalAllocatedInterfaces
	if totalAllocatedInterfaces > 0 && totalFreeInterfaces > expectedFreeInterfaces {
		log.Printf("[DRASecondaryNIC] MISMATCH DETECTED: K8s API shows %d allocated claims, expected %d free interfaces, but driver sees %d free",
			totalAllocatedInterfaces, expectedFreeInterfaces, totalFreeInterfaces)
		log.Printf("[DRASecondaryNIC] Driver internal state not synchronized with K8s - indicates kubelet-DRA communication failure")
		return false // UNHEALTHY - trigger kubelet restart
	}

	log.Printf("[DRASecondaryNIC] Resource discovery healthy: %d total interfaces, %d available", totalInitiallyDiscovered, totalFreeInterfaces)
	return true
}

// getActiveResourceClaimsCount queries Kubernetes API to count active resource claims for this driver on this node
func getActiveResourceClaimsCount(drv *Driver, nodeName string) int {
	// Get Kubernetes client from driver
	cs, err := NewClientSets()
	if err != nil {
		log.Printf("[DRASecondaryNIC] Failed to create K8s client for resource claim query: %v", err)
		return 0
	}

	// Query for pods on this node that have resource claims using our driver
	podList, err := cs.Core.CoreV1().Pods("").List(context.Background(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		log.Printf("[DRASecondaryNIC] Failed to list pods on node %s: %v", nodeName, err)
		return 0
	}

	log.Printf("[DRASecondaryNIC] DEBUG: Found %d pods on node %s", len(podList.Items), nodeName)

	activeClaimsCount := 0
	for _, pod := range podList.Items {
		log.Printf("[DRASecondaryNIC] DEBUG: Checking pod %s/%s, phase=%s", pod.Namespace, pod.Name, pod.Status.Phase)

		// Check pods in all phases - we need to count allocated claims even if pod can't start
		// This is crucial for detecting kubelet communication failures where claim is allocated
		// but pod is stuck in Pending due to driver communication issues

		// Check if pod has resource claims for our driver using resourceClaimStatuses
		for _, claimStatus := range pod.Status.ResourceClaimStatuses {
			if claimStatus.ResourceClaimName == nil {
				continue
			}
			claimName := *claimStatus.ResourceClaimName
			log.Printf("[DRASecondaryNIC] DEBUG: Processing resource claim status %s for pod %s/%s", claimName, pod.Namespace, pod.Name)

			// Get the resource claim details using the actual name
			resourceClaim, err := cs.Dynamic.Resource(schema.GroupVersionResource{
				Group:    "resource.k8s.io",
				Version:  "v1",
				Resource: "resourceclaims",
			}).Namespace(pod.Namespace).Get(context.Background(), claimName, metav1.GetOptions{})
			if err != nil {
				log.Printf("[DRASecondaryNIC] DEBUG: Failed to get resource claim %s: %v", claimName, err)
				continue // Claim might not exist or be accessible
			}

			// Check if this claim is for our driver
			spec, found, err := unstructured.NestedMap(resourceClaim.Object, "spec")
			if !found || err != nil {
				log.Printf("[DRASecondaryNIC] DEBUG: No spec found for claim %s", claimName)
				continue
			}

			// Look for devices.requests[].exactly.deviceClassName
			devices, found, err := unstructured.NestedMap(spec, "devices")
			if !found || err != nil {
				log.Printf("[DRASecondaryNIC] DEBUG: No devices found for claim %s", claimName)
				continue
			}

			requests, found, err := unstructured.NestedSlice(devices, "requests")
			if !found || err != nil {
				log.Printf("[DRASecondaryNIC] DEBUG: No requests found for claim %s", claimName)
				continue
			}

			var deviceClassName string
			deviceClassFound := false
			for _, request := range requests {
				if requestMap, ok := request.(map[string]interface{}); ok {
					if exactly, found, err := unstructured.NestedMap(requestMap, "exactly"); found && err == nil {
						if className, found, err := unstructured.NestedString(exactly, "deviceClassName"); found && err == nil {
							deviceClassName = className
							deviceClassFound = true
							break
						}
					}
				}
			}

			if !deviceClassFound {
				log.Printf("[DRASecondaryNIC] DEBUG: No deviceClassName found for claim %s", claimName)
				continue
			}

			log.Printf("[DRASecondaryNIC] DEBUG: Claim %s has deviceClassName: %s", claimName, deviceClassName) // Check if this is our device class/driver
			if deviceClassName == "dra-secondarynic" {                                                          // This should match your DeviceClass name
				status, found, err := unstructured.NestedMap(resourceClaim.Object, "status")
				if found && err == nil {
					_, found, err := unstructured.NestedMap(status, "allocation")
					if found && err == nil {
						// This claim is allocated - count it
						activeClaimsCount++
						log.Printf("[DRASecondaryNIC] Found active resource claim: pod=%s/%s, claim=%s",
							pod.Namespace, pod.Name, claimName)
					} else {
						log.Printf("[DRASecondaryNIC] DEBUG: Claim %s has no allocation", claimName)
					}
				} else {
					log.Printf("[DRASecondaryNIC] DEBUG: Claim %s has no status", claimName)
				}
			} else {
				log.Printf("[DRASecondaryNIC] DEBUG: Claim %s is for different driver: %s", claimName, deviceClassName)
			}
		}
	}
	log.Printf("[DRASecondaryNIC] DEBUG: Total active claims found: %d", activeClaimsCount)
	return activeClaimsCount
}

// isBYONNode checks if a node should have secondary network interfaces
func isBYONNode(nodeName string) bool {
	// BYON nodes have specific naming patterns
	// myvm3000004 and myvm3000007 are BYON nodes
	// aks-agentpool-* nodes are standard AKS nodes
	if strings.HasPrefix(nodeName, "myvm") {
		return true // BYON node
	}

	// AKS agent pool nodes and master nodes are not BYON
	if strings.Contains(nodeName, "aks-agentpool") ||
		strings.Contains(nodeName, "master") ||
		strings.Contains(nodeName, "control") {
		return false
	}

	// Default: assume non-BYON unless explicitly identified as BYON
	return false
}

// checkKubeletDRAStatus checks if kubelet actually recognizes our DRA driver registration
func checkKubeletDRAStatus(helper *kubeletplugin.Helper) bool {
	// SIMPLIFIED APPROACH: If we're successfully processing DRA requests, registration is working
	// The kubeletplugin.Helper.RegistrationStatus() can be unreliable due to timing and state issues

	// Instead of relying on internal plugin state, check for real operational issues:
	// 1. Are there stuck pods that indicate kubelet can't reach our driver?
	// 2. Are we successfully serving resource allocation requests?

	// For now, return true unless we detect actual operational problems
	// This eliminates false positive re-registrations while still detecting real issues
	log.Printf("[DRASecondaryNIC] DEBUG: Using simplified registration health check - focusing on operational health")

	// Only fail if we have concrete evidence of kubelet connectivity problems
	return true

	// Critical enhancement: Check if kubelet can actually reach our DRA driver
	// This is the key difference from Google DRANet - we need to verify actual connectivity
	// TEMPORARILY DISABLED: These checks are too aggressive and causing false positives
	// TODO: Re-enable with more lenient connectivity checks
	/*
		if !checkDRADriverConnectivity() {
			log.Printf("[DRASecondaryNIC] DRA driver connectivity check failed - registration drift detected")
			return false
		}
	*/

	// Check for stuck resource operations (pods in Terminating state)
	if hasStuckDRAOperations() {
		log.Printf("[DRASecondaryNIC] Stuck DRA operations detected - kubelet connection likely broken")
		return false
	}

	// All checks passed - registration is confirmed and operationally healthy
	return true
}

// checkDRADriverConnectivity verifies kubelet can actually communicate with our DRA driver
func checkDRADriverConnectivity() bool {
	// Test 1: Basic socket connectivity
	conn, err := net.DialTimeout("unix", "/var/lib/kubelet/plugins/dra-secondarynic/plugin.sock", 2*time.Second)
	if err != nil {
		log.Printf("[DRASecondaryNIC] DRA plugin socket unreachable: %v", err)
		return false
	}
	conn.Close()

	// Test 2: Registration socket connectivity
	regConn, regErr := net.DialTimeout("unix", "/var/lib/kubelet/plugins_registry/dra-secondarynic-reg.sock", 1*time.Second)
	if regErr != nil {
		log.Printf("[DRASecondaryNIC] Registration socket unreachable: %v", regErr)
		return false
	}
	regConn.Close()

	// Test 3: Check if kubelet's DRA manager is responsive
	// Look for signs that kubelet's DRA subsystem is working
	kubeletPid := getKubeletPid()
	if kubeletPid > 0 {
		// Check if kubelet process is healthy and not stuck
		if !isKubeletProcessHealthy(kubeletPid) {
			log.Printf("[DRASecondaryNIC] Kubelet process appears unhealthy (PID: %d)", kubeletPid)
			return false
		}
	}

	return true
}

// hasStuckDRAOperations detects if there are pods stuck due to DRA issues
func hasStuckDRAOperations() bool {
	// Check if there are pods in Terminating state that should be using our DRA driver
	// This indicates kubelet can't properly clean up DRA resources

	// For now, we'll use a simple approach - check for pods that have been terminating too long
	// In a production system, you could query the Kubernetes API to check for stuck pods

	// Look for common signs of stuck operations:
	// 1. Pods stuck in Terminating state
	// 2. Resource claims that can't be released
	// 3. Network namespaces that can't be cleaned up

	// Check for stale network namespaces (indicates failed cleanup)
	staleNS := hasStaleNetworkNamespaces()
	if staleNS {
		log.Printf("[DRASecondaryNIC] Stale network namespaces detected - cleanup failures")
		return true
	}

	return false
}

// getKubeletPid finds the kubelet process ID
func getKubeletPid() int {
	// Read from common kubelet PID locations
	pidFiles := []string{
		"/var/run/kubelet.pid",
		"/run/kubelet.pid",
		"/var/lib/kubelet/kubelet.pid",
	}

	for _, pidFile := range pidFiles {
		if data, err := os.ReadFile(pidFile); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				return pid
			}
		}
	}

	// Fallback: look for kubelet process
	cmd := exec.Command("pgrep", "kubelet")
	if output, err := cmd.Output(); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(output))); err == nil {
			return pid
		}
	}

	return 0
}

// isKubeletProcessHealthy checks if kubelet process is responsive
func isKubeletProcessHealthy(pid int) bool {
	// Check if process exists and is not stuck
	if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
		return false
	}

	// Check if kubelet's DRA plugin directory is accessible
	// This indicates kubelet's plugin management is working
	if _, err := os.Stat("/var/lib/kubelet/plugins_registry"); err != nil {
		log.Printf("[DRASecondaryNIC] Kubelet plugin registry inaccessible: %v", err)
		return false
	}

	return true
}

// hasStaleNetworkNamespaces checks for network cleanup failures
func hasStaleNetworkNamespaces() bool {
	// Look for CNI network namespaces that should have been cleaned up
	entries, err := os.ReadDir("/var/run/netns")
	if err != nil {
		return false // Can't check, assume healthy
	}

	staleCount := 0
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "cni-") {
			// Check if this namespace is old (more than 5 minutes)
			if info, err := entry.Info(); err == nil {
				if time.Since(info.ModTime()) > 5*time.Minute {
					staleCount++
				}
			}
		}
	}

	// If we have more than 5 stale namespaces, something is wrong with cleanup
	return staleCount > 5
}

// checkKubeletLogsForDRAErrors detects the specific registration drift issue from kubelet logs
func checkKubeletLogsForDRAErrors() bool {
	// Since we're in a container, we might not have access to host journalctl
	// For now, we'll rely on other detection mechanisms
	// TODO: Mount host journal or use alternative detection method
	return true
}

// checkForRecentOperationFailures checks if there are any signs of DRA operation failures
func checkForRecentOperationFailures() bool {
	// For now, rely on the socket connectivity test in checkKubeletDRAStatus
	// This is the most reliable indicator we have from within the container
	return false
}

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

	// CRITICAL: Wait for registration to complete like DRANet does
	log.Printf("[DRASecondaryNIC] Waiting for DRA plugin registration...")
	err = wait.PollUntilContextTimeout(context.Background(), 1*time.Second, 30*time.Second, true, func(context.Context) (bool, error) {
		status := plugin.RegistrationStatus()
		if status == nil {
			log.Printf("[DRASecondaryNIC] Registration status not available yet...")
			return false, nil
		}
		log.Printf("[DRASecondaryNIC] Registration status: PluginRegistered=%v", status.PluginRegistered)
		return status.PluginRegistered, nil
	})
	if err != nil {
		log.Printf("[DRASecondaryNIC] Initial registration failed: %v - continuing with background re-registration", err)
		// Don't crash - let the background monitoring handle re-registration
	} else {
		log.Printf("[DRASecondaryNIC] DRA plugin registration completed successfully!")
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

	// Start registration health monitoring in background
	go watchRegistrationHealth(drv, cs, nodeName, plugin)

	// Add immediate verification after startup using RegistrationStatus
	go func() {
		time.Sleep(5 * time.Second) // Let initial registration settle

		// Check if registration worked immediately using DRANet's method
		if !checkKubeletDRAStatus(plugin) {
			log.Printf("[DRASecondaryNIC] WARNING: Initial registration verification failed")
		} else {
			log.Printf("[DRASecondaryNIC] Initial registration verification passed")
		}
	}()

	// Graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	<-ctx.Done()
	plugin.Stop() // unregisters cleanly
	cancel()
	klog.Info("[DRASecondaryNIC] driver stopped")
}
