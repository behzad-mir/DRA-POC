// SPDX-License-Identifier: MIT
// Minimal DRA Node driver for Kubernetes v1.33.3 (DRA plugin API v1beta1).
// - Publishes a CDI device per ResourceClaim so your NRI hook can wire a NIC.
// - Allocates from a small pool or creates a dummy NIC when pool is empty.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	// Kubelet DRA plugin API for 1.33.x
	dra "k8s.io/kubelet/pkg/apis/dra/v1beta1"
	// Kubelet plugin registration (plugin-watcher handshake)
	regv1 "k8s.io/kubelet/pkg/apis/pluginregistration/v1"

	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

const (
	DriverName        = "dra-secondarynic" // MUST match your DeviceClass/ResourceSlice .spec.driver
	PluginDir         = "/var/lib/kubelet/plugins/" + DriverName
	PluginSocketPath  = PluginDir + "/plugin.sock"
	RegistrySocket    = "/var/lib/kubelet/plugins_registry/" + DriverName + ".sock"
	CDIRoot           = "/var/run/cdi"
	CDIKind           = "example.com/nic" // CDI device kind: <vendor or domain>/<kind>
	defaultCIDRForPOC = "10.9.255.5/24"   // optional POC IP; safe to leave "" if not needed
)

// ---------------- Internals ----------------

type Params struct {
	NICName string `json:"nicName"`
	IP      string `json:"ip,omitempty"`
	GW      string `json:"gw,omitempty"`
	DNS     string `json:"dns,omitempty"`
}

type Driver struct {
	dra.UnimplementedDRAPluginServer

	mu     sync.Mutex
	free   []string          // pool of host NIC names to reuse
	claims map[string]string // claimUID -> host NIC name
}

func NewDriver(initialPool []string) *Driver {
	return &Driver{
		free:   append([]string(nil), initialPool...),
		claims: make(map[string]string),
	}
}

// ---------------- DRA v1beta1 server ----------------

func (d *Driver) NodePrepareResources(ctx context.Context, req *dra.NodePrepareResourcesRequest) (*dra.NodePrepareResourcesResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := &dra.NodePrepareResourcesResponse{
		Claims: map[string]*dra.NodePrepareResourceResponse{},
	}

	for _, c := range req.GetClaims() {
		uid := c.GetUID()

		nicHost, created, err := d.pickOrCreateNICLocked()
		if err != nil {
			out.Claims[uid] = &dra.NodePrepareResourceResponse{Error: fmt.Sprintf("allocate NIC: %v", err)}
			continue
		}

		// Fill parameters for CDI/NRI; IMPORTANT: use the actual host NIC name.
		p := Params{
			NICName: nicHost,
			IP:      defaultCIDRForPOC, // optional; you can leave "" and let NRI configure inside netns
		}

		// (Optional) give the NIC an IP on the host first; NRI can also do this inside the pod.
		if p.IP != "" {
			if err := assignIP(nicHost, p.IP); err != nil {
				log.Printf("[DRASecondaryNIC] warn: assign IP on %s: %v", nicHost, err)
			}
		}

		// Write CDI device spec exporting env consumed by your NRI plugin.
		devName := "nic-" + uid
		if err := writeCDISpec(devName, p); err != nil {
			if created && strings.HasPrefix(nicHost, "dummy") {
				_ = delDummy(nicHost)
			}
			out.Claims[uid] = &dra.NodePrepareResourceResponse{Error: fmt.Sprintf("CDI write: %v", err)}
			continue
		}

		d.claims[uid] = nicHost

		// Return a single CDI device ID to kubelet (per-claim).
		out.Claims[uid] = &dra.NodePrepareResourceResponse{
			Devices: []*dra.Device{{
				CDIDeviceIDs: []string{fmt.Sprintf("%s:%s", CDIKind, devName)},
				DeviceName:   devName,
				// PoolName/RequestNames optional; omit for this POC
			}},
		}

		log.Printf("[DRASecondaryNIC] prepared claim=%s hostNIC=%s params=%+v", uid, nicHost, p)
	}

	return out, nil
}

func (d *Driver) NodeUnprepareResources(ctx context.Context, req *dra.NodeUnprepareResourcesRequest) (*dra.NodeUnprepareResourcesResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := &dra.NodeUnprepareResourcesResponse{
		Claims: map[string]*dra.NodeUnprepareResourceResponse{},
	}

	for _, c := range req.GetClaims() {
		uid := c.GetUID()
		devName := "nic-" + uid

		_ = os.Remove(filepath.Join(CDIRoot, devName+".json"))

		if nicHost, ok := d.claims[uid]; ok {
			delete(d.claims, uid)
			if strings.HasPrefix(nicHost, "dummy") {
				_ = delDummy(nicHost)
			} else {
				d.releaseNICLocked(nicHost)
			}
			log.Printf("[DRASecondaryNIC] unprepared claim=%s hostNIC=%s", uid, nicHost)
		}
		out.Claims[uid] = &dra.NodeUnprepareResourceResponse{} // empty error == success
	}
	return out, nil
}

// ---------------- NIC helpers ----------------

func (d *Driver) pickOrCreateNICLocked() (string, bool, error) {
	if len(d.free) > 0 {
		n := d.free[len(d.free)-1]
		d.free = d.free[:len(d.free)-1]
		return n, false, nil
	}
	name := nextDummyName()
	if err := addDummy(name); err != nil {
		return "", false, err
	}
	return name, true, nil
}
func (d *Driver) releaseNICLocked(nic string) { d.free = append(d.free, nic) }

func nextDummyName() string {
	for i := 0; i < 100; i++ {
		n := fmt.Sprintf("dummy%d", i)
		if _, err := os.Stat("/sys/class/net/" + n); os.IsNotExist(err) {
			return n
		}
	}
	return "dummy99"
}
func addDummy(name string) error {
	if err := execCmd("ip", "link", "add", name, "type", "dummy"); err != nil {
		return err
	}
	return execCmd("ip", "link", "set", name, "up")
}
func delDummy(name string) error      { return execCmd("ip", "link", "del", name) }
func assignIP(nic, addr string) error { return execCmd("ip", "addr", "add", addr, "dev", nic) }

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
	Env []kv `json:"env,omitempty"`
}
type kv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

func writeCDISpec(deviceName string, p Params) error {
	spec := cdiSpec{
		CDIVersion: "0.8.0",
		Kind:       CDIKind,
		Devices: []cdiDevice{{
			Name:        deviceName,
			Annotations: map[string]string{"NRI_NIC_NAME": p.NICName, "NRI_NIC_IP": p.IP, "NRI_NIC_GW": p.GW, "NRI_NIC_DNS": p.DNS},
			ContainerEdits: &containerEdits{
				Env: []kv{
					{Name: "NRI_NIC_NAME", Value: p.NICName},
					{Name: "NRI_NIC_IP", Value: p.IP},
					{Name: "NRI_NIC_GW", Value: p.GW},
					{Name: "NRI_NIC_DNS", Value: p.DNS},
				},
			},
		}},
	}
	if err := os.MkdirAll(CDIRoot, 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(spec, "", "  ")
	return os.WriteFile(filepath.Join(CDIRoot, deviceName+".json"), b, 0o644)
}

// ---------------- Registration server ----------------

type regServer struct {
	regv1.UnimplementedRegistrationServer
}

func (s *regServer) GetInfo(ctx context.Context, _ *regv1.InfoRequest) (*regv1.PluginInfo, error) {

	info := &regv1.PluginInfo{
		Type: "DRAPlugin",
		Name: DriverName,
		//Endpoint:          "/var/lib/kubelet/plugins/dra-secondarynic/plugin.sock",
		Endpoint:          "plugin.sock", // ← relative
		SupportedVersions: []string{"v1beta1"},
	}
	log.Printf("[DRASecondaryNIC] GetInfo -> Name=%q Endpoint=%q Versions=%v",
		info.Name, info.Endpoint, info.SupportedVersions)
	return info, nil

}
func (s *regServer) NotifyRegistrationStatus(ctx context.Context, st *regv1.RegistrationStatus) (*regv1.RegistrationStatusResponse, error) {
	if !st.GetPluginRegistered() {
		log.Printf("[DRASecondaryNIC] kubelet registration FAILED: %s", st.GetError())
	} else {
		log.Printf("[DRASecondaryNIC] kubelet registration SUCCEEDED")
	}

	log.Printf("[DRASecondaryNIC] NotifyRegistrationStatus -> registered=%v error=%q",
		st.GetPluginRegistered(), st.GetError())

	return &regv1.RegistrationStatusResponse{}, nil
}

// ---------------- main ----------------

func main() {
	if err := os.MkdirAll(PluginDir, 0o755); err != nil {
		log.Fatalf("create plugin dir: %v", err)
	}

	// DRA node server (driver endpoint)
	_ = os.Remove(PluginSocketPath)
	nodeLis, err := net.Listen("unix", PluginSocketPath)
	if err != nil {
		log.Fatalf("listen node socket: %v", err)
	}
	// ✅ Ensure kubelet can access the socket
	if err := os.Chmod(PluginSocketPath, 0777); err != nil {
		log.Printf("[DRASecondaryNIC] warn: failed to chmod socket: %v", err)
	}

	// ✅ Fallback symlink for kubelet bug in v1.33 (raw endpoint interpretation)
	fallbackDir := "/dra-secondarynic"
	fallbackSock := fallbackDir + "/plugin.sock"
	if err := os.MkdirAll(fallbackDir, 0755); err == nil {
		_ = os.Remove(fallbackSock)
		if err := os.Symlink(PluginSocketPath, fallbackSock); err != nil {
			log.Printf("[DRASecondaryNIC] warn: failed to create fallback symlink: %v", err)
		} else {
			log.Printf("[DRASecondaryNIC] created fallback symlink at %s", fallbackSock)
		}
	}
	nodeSrv := grpc.NewServer()
	dra.RegisterDRAPluginServer(nodeSrv, NewDriver(nil)) // pass a pool like []string{"eth1"} to reuse a real NIC
	reflection.Register(nodeSrv)
	go func() {
		log.Printf("[DRASecondaryNIC] Node listening on %s", PluginSocketPath)
		if err := nodeSrv.Serve(nodeLis); err != nil {
			log.Fatalf("node server error: %v", err)
		}
	}()

	// Registration server for kubelet plugin-watcher
	_ = os.Remove(RegistrySocket)
	regLis, err := net.Listen("unix", RegistrySocket)
	if err != nil {
		log.Fatalf("listen registry socket: %v", err)
	}
	regSrv := grpc.NewServer()
	regv1.RegisterRegistrationServer(regSrv, &regServer{})
	reflection.Register(regSrv)
	go func() {
		log.Printf("[DRASecondaryNIC] Registration listening on %s", RegistrySocket)
		if err := regSrv.Serve(regLis); err != nil {
			log.Fatalf("registration server error: %v", err)
		}
	}()

	// Graceful shutdown
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	<-ctx.Done()
	regSrv.GracefulStop()
	nodeSrv.GracefulStop()
	cancel()
	log.Println("[DRASecondaryNIC] driver stopped")
}
