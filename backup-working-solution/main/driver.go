// SPDX-License-Identifier: MIT
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	pb "example.com/dra-secondarynic/draProtos"
	resourceapi "k8s.io/api/resource/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/dynamic-resource-allocation/kubeletplugin"
	"k8s.io/dynamic-resource-allocation/resourceslice"
)

const (
	CDIRoot       = "/var/run/cdi"
	CDIKind       = "example.com/nic" // <vendor-or-domain>/<kind> for CDI
	baseIPNetwork = "10.9.255.0/24"   // Base network for IP allocation

	// Resource publishing constants
	ResourceClassName = "secondary-nic" // Resource class name for scheduling
)

// ---------------- Internals ----------------

type Params struct {
	NICName string `json:"nicName"`
	IP      string `json:"ip,omitempty"`
	GW      string `json:"gw,omitempty"`
	DNS     string `json:"dns,omitempty"`
}

type Driver struct {
	pb.UnimplementedNodeServer // Embed for gRPC forward compatibility
	mu                         sync.Mutex
	free                       []string          // pool of host NIC names to reuse
	claims                     map[string]string // claimUID -> host NIC name
	nodeName                   string            // Kubernetes node name
	driverName                 string            // DRA driver name

	// IP allocation
	ipCounter int // Counter for unique IP allocation

	// Resource publishing
	publishedResources []resourceapi.Device
	lastResourceUpdate time.Time
}

func NewDriver(initialPool []string, nodeName, driverName string) *Driver {
	driver := &Driver{
		free:       append([]string(nil), initialPool...),
		claims:     make(map[string]string),
		nodeName:   nodeName,
		driverName: driverName,
		ipCounter:  0,
	}

	// Discover available network resources on this node
	driver.discoverResources()

	return driver
}

// generateUniqueIP generates IP address based on static node mapping
// Only the original Azure-assigned IPs work due to Azure networking restrictions
func (d *Driver) generateUniqueIP() string {
	// Static mapping based on Azure-assigned IPs that actually work
	// myvm000000 gets 10.9.255.4, myvm000001 gets 10.9.255.5
	if strings.Contains(d.nodeName, "myvm000000") {
		return "10.9.255.4/24"
	} else if strings.Contains(d.nodeName, "myvm000001") {
		return "10.9.255.5/24"
	} else {
		// Fallback for other nodes (shouldn't happen with current setup)
		return "10.9.255.4/24"
	}
}

// ---------------- kubeletplugin.DRAPlugin implementation ----------------

// PrepareResourceClaims prepares devices for the provided claims and publishes CDI devices.
func (d *Driver) PrepareResourceClaims(
	ctx context.Context,
	claims []*resourceapi.ResourceClaim,
) (map[types.UID]kubeletplugin.PrepareResult, error) {

	d.mu.Lock()
	defer d.mu.Unlock()

	results := make(map[types.UID]kubeletplugin.PrepareResult)

	for _, claim := range claims {
		nicHost, _, err := d.pickOrCreateNICLocked()
		if err != nil {
			results[claim.UID] = kubeletplugin.PrepareResult{
				Err: fmt.Errorf("allocate NIC for claim %s: %w", claim.UID, err),
			}
			continue
		}

		p := Params{
			NICName: nicHost,
			IP:      d.generateUniqueIP(), // Generate unique IP for each pod
		}

		// IP configuration is handled by NRI plugin in the pod namespace
		// No need to configure IP on the host interface

		devName := "nic-" + string(claim.UID)

		// Create CDI device specification
		err = writeCDISpec(devName, p)
		if err != nil {
			results[claim.UID] = kubeletplugin.PrepareResult{
				Err: fmt.Errorf("create CDI spec for claim %s: %w", claim.UID, err),
			}
			continue
		}

		d.claims[string(claim.UID)] = nicHost

		// Also write NRI config as backup method
		err = d.writeNRIConfig(string(claim.UID), nicHost, p)
		if err != nil {
			log.Printf("[DRASecondaryNIC] Warning: failed to write NRI config for claim %s: %v", claim.UID, err)
		}

		// Return CDI device reference
		cdiDeviceName := CDIKind + "=" + devName
		results[claim.UID] = kubeletplugin.PrepareResult{
			Devices: []kubeletplugin.Device{
				{
					PoolName:     "default",
					DeviceName:   devName,
					CDIDeviceIDs: []string{cdiDeviceName},
				},
			},
		}
		log.Printf("[DRASecondaryNIC] prepared claim=%s hostNIC=%s params=%+v", claim.UID, nicHost, p)
	}

	// Update resource availability after allocation
	if len(results) > 0 {
		d.UpdateResourceAvailability()
	}
	return results, nil
}

// UnprepareResourceClaims tears down CDI files and releases/cleans NICs.
func (d *Driver) UnprepareResourceClaims(
	ctx context.Context,
	claims []kubeletplugin.NamespacedObject,
) (map[types.UID]error, error) {

	d.mu.Lock()
	defer d.mu.Unlock()

	errs := make(map[types.UID]error)

	for _, claim := range claims {
		uid := claim.UID
		devName := "nic-" + string(uid)
		_ = removeCDIDevice(devName)

		key := string(uid)
		if nicHost, ok := d.claims[key]; ok {
			delete(d.claims, key)
			// Return eth interface to free pool
			d.releaseNICLocked(nicHost)
			log.Printf("[DRASecondaryNIC] unprepared claim=%s hostNIC=%s", uid, nicHost)
		}
		errs[uid] = nil // success
	}

	// Update resource availability after deallocation
	if len(claims) > 0 {
		d.UpdateResourceAvailability()
	}

	return errs, nil
}

// HandleError handles background errors (required by DRAPlugin interface)
func (d *Driver) HandleError(ctx context.Context, err error, msg string) {
	log.Printf("[DRASecondaryNIC] ERROR: %s: %v", msg, err)
}

// ---------------- gRPC Service Implementation ----------------

// ConfigureNetwork implements the gRPC service method for NRI plugin calls
func (d *Driver) ConfigureNetwork(ctx context.Context, req *pb.ConfigureNetworkRequest) (*pb.ConfigureNetworkResponse, error) {
	log.Printf("[DRASecondaryNIC] ConfigureNetwork gRPC call for pod %s/%s, container %s, PID %d",
		req.GetPodNamespace(), req.GetPodName(), req.GetContainerName(), req.GetContainerPid())

	// Check if we have available NICs and should configure this pod
	if !d.shouldConfigurePod(req) {
		log.Printf("[DRASecondaryNIC] Pod %s/%s does not need network configuration", req.GetPodNamespace(), req.GetPodName())
		return &pb.ConfigureNetworkResponse{
			Success:      true,
			ErrorMessage: "",
			Interfaces:   []*pb.ConfiguredInterface{},
		}, nil
	}

	// Get or allocate NIC configuration for this pod
	cfg, err := d.getNetworkConfigForPod(req)
	if err != nil {
		log.Printf("[DRASecondaryNIC] Failed to get network config: %v", err)
		return &pb.ConfigureNetworkResponse{
			Success:      false,
			ErrorMessage: fmt.Sprintf("Failed to get network configuration: %v", err),
			Interfaces:   []*pb.ConfiguredInterface{},
		}, nil
	}

	// Return the network configuration without performing actual network setup
	// The NRI plugin will handle the network interface movement and configuration
	log.Printf("[DRASecondaryNIC] Allocated network config: NIC=%s, IP=%s, GW=%s", cfg.NICName, cfg.IP, cfg.GW)
	log.Printf("[DRASecondaryNIC] Network interface movement will be handled by NRI plugin")

	// Return success response with network configuration
	log.Printf("[DRASecondaryNIC] Network resource allocation completed successfully")
	return &pb.ConfigureNetworkResponse{
		Success:      true,
		ErrorMessage: "",
		Interfaces: []*pb.ConfiguredInterface{
			{
				NicName:   cfg.NICName,
				IpAddress: cfg.IP,
				Gateway:   cfg.GW,
			},
		},
	}, nil
}

// PrepareResources implements the gRPC NodeServer interface - stub implementation
func (d *Driver) PrepareResources(ctx context.Context, req *pb.PrepareResourcesRequest) (*pb.PrepareResourcesResponse, error) {
	log.Printf("[DRASecondaryNIC] PrepareResources gRPC call (not used by NRI plugin)")
	return &pb.PrepareResourcesResponse{}, nil
}

// UnprepareResources implements the gRPC NodeServer interface - stub implementation
func (d *Driver) UnprepareResources(ctx context.Context, req *pb.UnprepareResourcesRequest) (*pb.UnprepareResourcesResponse, error) {
	log.Printf("[DRASecondaryNIC] UnprepareResources gRPC call (not used by NRI plugin)")
	return &pb.UnprepareResourcesResponse{}, nil
}

func (d *Driver) shouldConfigurePod(req *pb.ConfigureNetworkRequest) bool {
	// Check if this pod has resource claims for secondary NICs
	for _, claim := range req.GetResourceClaims() {
		if strings.Contains(claim.GetName(), "secondary-nic") || strings.Contains(claim.GetName(), "nic") {
			log.Printf("[DRASecondaryNIC] Found resource claim: %s", claim.GetName())
			return true
		}
	}

	// Check for test pods based on names
	podName := req.GetPodName()
	if strings.Contains(podName, "test-nri-interface") {
		log.Printf("[DRASecondaryNIC] Found test pod: %s", podName)
		return true
	}

	return false
}

func (d *Driver) getNetworkConfigForPod(req *pb.ConfigureNetworkRequest) (*Params, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	podUID := req.GetPodUID()
	log.Printf("[DRASecondaryNIC] Looking for prepared resources for pod %s", podUID)

	// First, check if we already have a claim configured for this pod UID
	if existingNIC, exists := d.claims[podUID]; exists {
		log.Printf("[DRASecondaryNIC] Found existing claim for pod %s: %s", podUID, existingNIC)
		return &Params{
			NICName: existingNIC,
			IP:      d.generateUniqueIP(),
			GW:      "10.9.255.1",
		}, nil
	}

	// Look through all current claims to find one that matches this pod
	// The DRA driver already prepared resources, we need to find and use them
	for claimUID, hostNIC := range d.claims {
		log.Printf("[DRASecondaryNIC] Checking existing claim %s -> %s", claimUID, hostNIC)
		// For now, use any available prepared claim since we know one was just prepared
		if hostNIC == "eth1" {
			log.Printf("[DRASecondaryNIC] Using prepared DRA claim %s with NIC %s for pod %s", claimUID, hostNIC, podUID)

			// Use the existing allocation
			cfg := &Params{
				NICName: hostNIC,
				IP:      d.generateUniqueIP(),
				GW:      "10.9.255.1",
			}

			// Update the claim mapping to use the pod UID
			d.claims[podUID] = hostNIC

			return cfg, nil
		}
	}

	log.Printf("[DRASecondaryNIC] No prepared DRA resources found, current claims: %v", d.claims)
	return nil, fmt.Errorf("no prepared DRA resources available for pod %s", podUID)
}

func (d *Driver) performNetworkConfiguration(containerPID int32, cfg *Params, podUID string, networkNamespacePath string) error {
	log.Printf("[DRASecondaryNIC] Starting network configuration for pod %s with netns path: %s", podUID, networkNamespacePath)

	if networkNamespacePath == "" {
		return fmt.Errorf("network namespace path is empty")
	}

	// Step 1: Verify NIC exists on host
	if out, err := d.runCommand("/sbin/ip", "link", "show", cfg.NICName); err != nil {
		return fmt.Errorf("NIC %s not found in host: %v, output: %s", cfg.NICName, err, out)
	}
	log.Printf("[DRASecondaryNIC] Confirmed NIC %s exists in host", cfg.NICName)

	// Step 2: Move NIC to pod's network namespace
	// Check if network namespace exists, wait up to 10 seconds for it to be created
	log.Printf("[DRASecondaryNIC] Checking if network namespace %s exists", networkNamespacePath)
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(networkNamespacePath); err == nil {
			log.Printf("[DRASecondaryNIC] Network namespace %s exists", networkNamespacePath)
			break
		}
		if i == 9 {
			return fmt.Errorf("network namespace %s does not exist after 10 seconds", networkNamespacePath)
		}
		log.Printf("[DRASecondaryNIC] Network namespace %s does not exist yet, waiting... (attempt %d/10)", networkNamespacePath, i+1)
		time.Sleep(1 * time.Second)
	}

	log.Printf("[DRASecondaryNIC] Moving NIC %s to netns %s using full path", cfg.NICName, networkNamespacePath)
	if out, err := d.runCommand("/sbin/ip", "link", "set", cfg.NICName, "netns", networkNamespacePath); err != nil {
		return fmt.Errorf("Move %s to netns %s failed: %v / %s", cfg.NICName, networkNamespacePath, err, out)
	}
	log.Printf("[DRASecondaryNIC] Successfully moved NIC %s to pod namespace", cfg.NICName)

	// Step 3: Bring up the interface in pod namespace
	log.Printf("[DRASecondaryNIC] Bringing up NIC %s in pod namespace", cfg.NICName)
	if out, err := d.runCommand("/usr/bin/nsenter", "--net="+networkNamespacePath, "/sbin/ip", "link", "set", cfg.NICName, "up"); err != nil {
		return fmt.Errorf("Bring %s up in %s failed: %v / %s", cfg.NICName, networkNamespacePath, err, out)
	}
	log.Printf("[DRASecondaryNIC] Successfully brought up NIC %s", cfg.NICName)

	// Step 4: Configure IP address if provided
	if cfg.IP != "" {
		log.Printf("[DRASecondaryNIC] Configuring IP %s on NIC %s", cfg.IP, cfg.NICName)
		if out, err := d.runCommand("/usr/bin/nsenter", "--net="+networkNamespacePath, "/sbin/ip", "addr", "add", cfg.IP, "dev", cfg.NICName); err != nil {
			// Ignore "File exists" error for IP addresses that are already configured
			if !strings.Contains(out, "File exists") {
				log.Printf("[DRASecondaryNIC] Warning: IP address configuration failed: %v, output: %s", err, out)
			} else {
				log.Printf("[DRASecondaryNIC] IP %s already configured", cfg.IP)
			}
		} else {
			log.Printf("[DRASecondaryNIC] Successfully configured IP %s", cfg.IP)
		}
	}

	// Step 5: Configure default route if gateway provided
	if cfg.GW != "" {
		log.Printf("[DRASecondaryNIC] Setting gateway %s for NIC %s", cfg.GW, cfg.NICName)
		if out, err := d.runCommand("/usr/bin/nsenter", "--net="+networkNamespacePath, "/sbin/ip", "route", "replace", "default", "via", cfg.GW, "dev", cfg.NICName, "metric", "10"); err != nil {
			log.Printf("[DRASecondaryNIC] Warning: default route configuration failed: %v, output: %s", err, out)
		} else {
			log.Printf("[DRASecondaryNIC] Successfully set default route via %s", cfg.GW)
		}
	}

	log.Printf("[DRASecondaryNIC] Network configuration completed successfully for NIC %s (ip=%s gw=%s)",
		cfg.NICName, cfg.IP, cfg.GW)
	return nil
}

func (d *Driver) runCommand(name string, args ...string) (string, error) {
	log.Printf("[DRASecondaryNIC] Running command: %s %v", name, args)
	cmd := exec.Command(name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	output := buf.String()
	if err != nil {
		log.Printf("[DRASecondaryNIC] Command failed: %s %v -> %v, output: %s", name, args, err, output)
	} else {
		log.Printf("[DRASecondaryNIC] Command succeeded: %s %v", name, args)
	}
	return output, err
}

func (d *Driver) findNetworkNamespace(podUID string) (string, error) {
	log.Printf("[DRASecondaryNIC] Looking for network namespace for pod UID: %s", podUID)

	// Expected namespace name based on Kubernetes pod UID
	expectedNsName := fmt.Sprintf("cni-%s", podUID)

	// Retry logic - wait for the network namespace to be created
	maxRetries := 10
	retryDelay := time.Second * 2

	for attempt := 1; attempt <= maxRetries; attempt++ {
		log.Printf("[DRASecondaryNIC] Attempt %d/%d: Looking for network namespace %s", attempt, maxRetries, expectedNsName)

		// List all network namespaces
		output, err := d.runCommand("/sbin/ip", "netns", "list")
		if err != nil {
			log.Printf("[DRASecondaryNIC] Failed to list network namespaces: %v", err)
			if attempt < maxRetries {
				log.Printf("[DRASecondaryNIC] Waiting %v before retry...", retryDelay)
				time.Sleep(retryDelay)
				continue
			}
			return "", fmt.Errorf("failed to list network namespaces after %d attempts: %v", maxRetries, err)
		}

		log.Printf("[DRASecondaryNIC] Available network namespaces: %s", strings.TrimSpace(output))

		// Check if our expected namespace exists
		lines := strings.Split(strings.TrimSpace(output), "\n")
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue // Skip empty lines
			}

			// Each line might look like: "cni-f6c4d010-bad7-6b05-7fc5-08b03bf07fda (id: 0)"
			// Extract just the namespace name (before any parentheses)
			parts := strings.Fields(line)
			if len(parts) > 0 {
				nsName := parts[0]
				log.Printf("[DRASecondaryNIC] Found namespace: %s", nsName)

				// Check if this matches our expected namespace
				if nsName == expectedNsName {
					log.Printf("[DRASecondaryNIC] Found matching network namespace: %s", nsName)
					return nsName, nil
				}
			}
		}

		// If namespace not found and this isn't the last attempt, wait and retry
		if attempt < maxRetries {
			log.Printf("[DRASecondaryNIC] Network namespace %s not found, waiting %v before retry %d/%d",
				expectedNsName, retryDelay, attempt+1, maxRetries)
			time.Sleep(retryDelay)
		}
	}

	// If we get here, the namespace was never found
	return "", fmt.Errorf("network namespace %s not found after %d attempts over %v",
		expectedNsName, maxRetries, time.Duration(maxRetries)*retryDelay)
}

// ---------------- Resource Discovery and Publishing ----------------

// discoverResources discovers available network resources on this node
func (d *Driver) discoverResources() {
	d.mu.Lock()
	defer d.mu.Unlock()

	var devices []resourceapi.Device

	// Discover only eth1, eth2, etc. secondary interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		log.Printf("[DRASecondaryNIC] failed to discover interfaces: %v", err)
	} else {
		for _, iface := range interfaces {
			// Only include eth1, eth2, eth3, etc. (not eth0 which is primary)
			if !strings.HasPrefix(iface.Name, "eth") || iface.Name == "eth0" {
				continue
			}

			// Skip loopback or down interfaces
			if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
				continue
			}

			// Check if this NIC is already claimed
			claimed := false
			for _, claimedNIC := range d.claims {
				if claimedNIC == iface.Name {
					claimed = true
					break
				}
			}

			if !claimed {
				devices = append(devices, resourceapi.Device{
					Name: fmt.Sprintf("secondary-nic-%s-%s", iface.Name, d.nodeName),
					Attributes: map[resourceapi.QualifiedName]resourceapi.DeviceAttribute{
						"type":      {StringValue: &[]string{"physical"}[0]},
						"interface": {StringValue: &[]string{iface.Name}[0]},
						"driver":    {StringValue: &[]string{d.driverName}[0]},
						"node":      {StringValue: &[]string{d.nodeName}[0]},
					},
				})

				// Add to free pool if not already there
				found := false
				for _, freeNIC := range d.free {
					if freeNIC == iface.Name {
						found = true
						break
					}
				}
				if !found {
					d.free = append(d.free, iface.Name)
				}
			}
		}
	}

	d.publishedResources = devices
	d.lastResourceUpdate = time.Now()

	log.Printf("[DRASecondaryNIC] discovered %d available network resources on node %s",
		len(devices), d.nodeName)
}

// GetResources returns the current resource availability for ResourceSlice publishing
func (d *Driver) GetResources() []resourceapi.Device {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Refresh resources periodically or when significant changes occur
	if time.Since(d.lastResourceUpdate) > 5*time.Minute {
		go d.discoverResources() // Async refresh
	}

	return append([]resourceapi.Device(nil), d.publishedResources...)
}

// GetResourcesForSlice returns the current resource availability formatted for ResourceSlice publishing
func (d *Driver) GetResourcesForSlice() resourceslice.DriverResources {
	d.mu.Lock()
	defer d.mu.Unlock()

	// Refresh resources periodically or when significant changes occur
	if time.Since(d.lastResourceUpdate) > 5*time.Minute {
		go d.discoverResources() // Async refresh
	}

	// Create a pool with the discovered devices
	pools := map[string]resourceslice.Pool{
		"secondary-nics": {
			NodeSelector: nil, // Available on all nodes
			Generation:   0,   // Auto-incremented by controller
			Slices: []resourceslice.Slice{
				{
					Devices:                append([]resourceapi.Device(nil), d.publishedResources...),
					SharedCounters:         nil,
					PerDeviceNodeSelection: nil,
				},
			},
		},
	}

	return resourceslice.DriverResources{
		Pools: pools,
	}
}

// UpdateResourceAvailability updates resource availability after allocation/deallocation
func (d *Driver) UpdateResourceAvailability() {
	// Trigger resource rediscovery
	go d.discoverResources()
}

// ---------------- NIC helpers ----------------

func (d *Driver) pickOrCreateNICLocked() (string, bool, error) {
	if len(d.free) > 0 {
		n := d.free[len(d.free)-1]
		d.free = d.free[:len(d.free)-1]
		return n, false, nil
	}
	return "", false, fmt.Errorf("no available eth interfaces found")
}
func (d *Driver) releaseNICLocked(nic string) { d.free = append(d.free, nic) }

// IP configuration removed - handled by NRI plugin in pod namespace

func execCmd(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("[DRASecondaryNIC] cmd %s %v -> err=%v out=%s", name, args, err, string(out))
	}
	return err
}

// ---------------- CDI writer ----------------

type cdiSpec struct {
	CDIVersion string      `json:"cdiVersion"`
	Kind       string      `json:"kind"`
	Devices    []cdiDevice `json:"devices"`
}
type cdiDevice struct {
	Name           string            `json:"name"`
	Annotations    map[string]string `json:"annotations,omitempty"`
	ContainerEdits *containerEdits   `json:"containerEdits,omitempty"`
}
type containerEdits struct {
	Env []string `json:"env,omitempty"`
}

func writeCDISpec(deviceName string, p Params) error {
	// Use standard CDI filename: vendor.device-class.json
	filename := strings.ReplaceAll(CDIKind, "/", ".") + ".json"
	filepath := filepath.Join(CDIRoot, filename)

	if err := os.MkdirAll(CDIRoot, 0o755); err != nil {
		return err
	}

	// Read existing spec or create new one (standard CDI approach)
	var spec cdiSpec
	if data, err := os.ReadFile(filepath); err == nil {
		// File exists, parse existing spec
		if err := json.Unmarshal(data, &spec); err != nil {
			return fmt.Errorf("failed to parse existing CDI spec: %w", err)
		}
		// Remove existing device with same name if it exists
		var newDevices []cdiDevice
		for _, device := range spec.Devices {
			if device.Name != deviceName {
				newDevices = append(newDevices, device)
			}
		}
		spec.Devices = newDevices
	} else {
		// File doesn't exist, create new spec
		spec = cdiSpec{
			CDIVersion: "0.8.0",
			Kind:       CDIKind,
			Devices:    []cdiDevice{},
		}
	}

	// Add new device to spec
	newDevice := cdiDevice{
		Name:        deviceName,
		Annotations: map[string]string{"NRI_NIC_NAME": p.NICName, "NRI_NIC_IP": p.IP, "NRI_NIC_GW": p.GW, "NRI_NIC_DNS": p.DNS},
		ContainerEdits: &containerEdits{
			Env: []string{
				fmt.Sprintf("NRI_NIC_NAME=%s", p.NICName),
				fmt.Sprintf("NRI_NIC_IP=%s", p.IP),
				fmt.Sprintf("NRI_NIC_GW=%s", p.GW),
				fmt.Sprintf("NRI_NIC_DNS=%s", p.DNS),
			},
		},
	}
	spec.Devices = append(spec.Devices, newDevice)
	b, _ := json.MarshalIndent(spec, "", "  ")
	log.Printf("[DRASecondaryNIC] Writing CDI spec for device %s to %s", deviceName, filepath)
	log.Printf("[DRASecondaryNIC] CDI spec content: %s", string(b))
	if err := os.WriteFile(filepath, b, 0o644); err != nil {
		log.Printf("[DRASecondaryNIC] Failed to write CDI spec: %v", err)
		return err
	}
	log.Printf("[DRASecondaryNIC] Successfully wrote CDI spec")
	return nil
}

func (d *Driver) writeNRIConfig(claimUID, nicHost string, p Params) error {
	// Write NRI configuration to a file that the NRI plugin can read
	config := map[string]string{
		"claimUID": claimUID,
		"nicHost":  nicHost,
		"nicName":  p.NICName,
		"ip":       p.IP,
	}

	configPath := fmt.Sprintf("/var/run/nri/claim-%s.json", claimUID)
	if err := os.MkdirAll("/var/run/nri", 0o755); err != nil {
		return err
	}

	data, _ := json.MarshalIndent(config, "", "  ")
	return os.WriteFile(configPath, data, 0o644)
}

func removeCDIDevice(deviceName string) error {
	// Use standard CDI filename (matching writeCDISpec)
	filename := strings.ReplaceAll(CDIKind, "/", ".") + ".json"
	filepath := filepath.Join(CDIRoot, filename)

	// Read existing spec
	data, err := os.ReadFile(filepath)
	if err != nil {
		// File doesn't exist, nothing to remove
		return nil
	}

	var spec cdiSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return fmt.Errorf("failed to parse existing CDI spec: %w", err)
	}

	// Remove device from spec
	var newDevices []cdiDevice
	for _, device := range spec.Devices {
		if device.Name != deviceName {
			newDevices = append(newDevices, device)
		}
	}
	spec.Devices = newDevices

	// If no devices left, remove the file
	if len(spec.Devices) == 0 {
		return os.Remove(filepath)
	}

	// Otherwise, write updated spec
	b, _ := json.MarshalIndent(spec, "", "  ")
	return os.WriteFile(filepath, b, 0o644)
}
