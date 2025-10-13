package agent

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/vishvananda/netlink"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	"netscope/pkg/byteorder"
	"netscope/pkg/payload"
)

const (
	// Collection interval
	defaultCollectionInterval = 10 * time.Second
)

type Agent struct {
	nodeName           string
	serverEndpoint     string
	collectionInterval time.Duration
	kubeClient         *kubernetes.Clientset
	objs               *netscopeObjects
	links              []link.Link
	podIPs             map[string]bool // Set of pod IPs on this node
}

type Config struct {
	NodeName           string
	ServerEndpoint     string
	CollectionInterval time.Duration
	KubeConfigPath     string
}

func NewAgent(cfg Config) (*Agent, error) {
	if cfg.CollectionInterval == 0 {
		cfg.CollectionInterval = defaultCollectionInterval
	}

	// Create Kubernetes client
	var config *rest.Config
	var err error

	if cfg.KubeConfigPath != "" {
		config, err = clientcmd.BuildConfigFromFlags("", cfg.KubeConfigPath)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes config: %w", err)
	}

	kubeClient, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &Agent{
		nodeName:           cfg.NodeName,
		serverEndpoint:     cfg.ServerEndpoint,
		collectionInterval: cfg.CollectionInterval,
		kubeClient:         kubeClient,
		podIPs:             make(map[string]bool),
		links:              make([]link.Link, 0),
	}, nil
}

func (a *Agent) Run(ctx context.Context) error {
	klog.InfoS("Starting netscope agent", "node", a.nodeName, "server", a.serverEndpoint)

	// Load eBPF program
	if err := a.loadEBPF(); err != nil {
		return fmt.Errorf("failed to load eBPF program: %w", err)
	}
	defer a.cleanup()

	// Start watching pods on this node
	if err := a.watchPods(ctx); err != nil {
		return fmt.Errorf("failed to watch pods: %w", err)
	}

	// Attach eBPF programs to existing veth interfaces
	if err := a.attachToVethInterfaces(); err != nil {
		klog.ErrorS(err, "Failed to attach to existing veth interfaces")
	}

	// Start collection loop
	klog.InfoS("Starting collection loop", "interval", a.collectionInterval)
	ticker := time.NewTicker(a.collectionInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			klog.InfoS("Agent shutting down")
			return nil
		case <-ticker.C:
			start := time.Now()
			klog.InfoS("Tick: starting collect and send")
			if err := a.collectAndSend(); err != nil {
				klog.ErrorS(err, "Failed to collect and send data")
			} else {
				klog.InfoS("Tick: completed collect and send", "duration", time.Since(start))
			}
		}
	}
}

func (a *Agent) loadEBPF() error {
	// Load eBPF objects
	objs := &netscopeObjects{}
	if err := loadNetscopeObjects(objs, nil); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			klog.ErrorS(err, "eBPF verifier error", "log", ve.Log)
		}
		return fmt.Errorf("failed to load eBPF objects: %w", err)
	}

	a.objs = objs
	klog.InfoS("eBPF program loaded successfully")
	return nil
}

// tcProgram returns the single TC sched_cls program used for both egress and ingress.
// Note: The field name 'TcEgress' is generated from the BPF function name 'tc_egress'.
// Even though it's called 'TcEgress', the program is direction-agnostic and can be
// attached to both egress and ingress hooks (TCX or legacy TC).
func (a *Agent) tcProgram() *ebpf.Program {
	if a.objs == nil {
		return nil
	}
	return a.objs.TcEgress
}

func (a *Agent) attachToVethInterfaces() error {
	// Get all network interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list network interfaces: %w", err)
	}

	attached := 0
	for _, iface := range ifaces {
		name := iface.Name
		// Attach to pod veth interfaces on host. On AWS VPC CNI these are typically named veth*, not eni*.
		// Keep support for eni* just in case of alternate setups.
		if strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "eni") || strings.HasPrefix(name, "cali") {
			if err := a.attachToInterface(name); err != nil {
				klog.ErrorS(err, "Failed to attach to interface", "interface", name)
				continue
			}
			attached++
		}
	}

	klog.InfoS("Attached eBPF programs to interfaces", "count", attached)
	return nil
}

func (a *Agent) attachToInterface(ifaceName string) error {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get interface %s: %w", ifaceName, err)
	}

	// Skip if interface is down
	if iface.Flags&net.FlagUp == 0 {
		klog.V(2).InfoS("Skipping down interface", "interface", ifaceName)
		return nil
	}

	// Try TCX first (kernel 6.6+): attach the same program to both egress and ingress
	lEgress, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   a.tcProgram(),
		Attach:    ebpf.AttachTCXEgress,
	})
	if err == nil {
		// Egress attached via TCX
		a.links = append(a.links, lEgress)
		// Try to attach ingress as well; if it fails, log and continue with egress-only
		lIngress, err2 := link.AttachTCX(link.TCXOptions{
			Interface: iface.Index,
			Program:   a.tcProgram(), // same sched_cls program works for ingress
			Attach:    ebpf.AttachTCXIngress,
		})
		if err2 == nil {
			a.links = append(a.links, lIngress)
			klog.V(2).InfoS("Attached eBPF program via TCX (ingress+egress)", "interface", ifaceName)
		} else {
			klog.V(2).InfoS("Attached eBPF program via TCX (egress only)", "interface", ifaceName, "error_ingress", err2)
		}
		return nil
	}

	// TCX not supported, use legacy TC via netlink (kernel 5.10+)
	klog.V(3).InfoS("TCX not supported, using legacy TC", "interface", ifaceName)

	// Get netlink handle
	nlLink, err := netlink.LinkByName(ifaceName)
	if err != nil {
		return fmt.Errorf("failed to get netlink link for %s: %w", ifaceName, err)
	}

	// Ensure clsact qdisc is present: always attempt to add and ignore if it already exists
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: nlLink.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err := netlink.QdiscAdd(qdisc); err != nil {
		// If it already exists, ignore the error. netlink doesn't expose a typed EEXIST, so match string.
		errStrQ := strings.ToLower(err.Error())
		if !strings.Contains(errStrQ, "file exists") && !strings.Contains(errStrQ, "exists") {
			return fmt.Errorf("failed to add clsact qdisc to %s: %w", ifaceName, err)
		}
	}

	// Add TC filters for multiple ethertypes so BPF runs for VLAN-tagged frames as well.
	// We support: IPv4 (0x0800), 802.1Q VLAN (0x8100), 802.1ad QinQ (0x88a8).
	protocols := []uint16{0x0800, 0x8100, 0x88a8}
	added := 0

	addFilters := func(parent uint32, direction, name string) {
		prio := 1
		for _, proto := range protocols {
			filter := &netlink.BpfFilter{
				FilterAttrs: netlink.FilterAttrs{
					LinkIndex: nlLink.Attrs().Index,
					Parent:    parent,
					Handle:    0, // let kernel assign
					Protocol:  proto,
					Priority:  uint16(prio),
				},
				Fd:           a.objs.TcEgress.FD(),
				Name:         name,
				DirectAction: true,
			}

			if err := netlink.FilterAdd(filter); err != nil {
				// If filter already exists, treat as success
				errStr := strings.ToLower(err.Error())
				if strings.Contains(errStr, "file exists") || strings.Contains(errStr, "exists") {
					klog.V(2).InfoS("TC filter already exists; skipping add", "interface", ifaceName, "dir", direction, "protocol", fmt.Sprintf("0x%04x", proto), "priority", prio)
					added++
					prio++
					continue
				}
				// Try without direct action mode as a fallback
				klog.V(3).InfoS("Failed with direct action, trying classifier mode", "interface", ifaceName, "dir", direction, "protocol", fmt.Sprintf("0x%04x", proto), "priority", prio, "error", err)
				filter.DirectAction = false
				if err := netlink.FilterAdd(filter); err != nil {
					// If still exists, treat as success
					errStr2 := strings.ToLower(err.Error())
					if strings.Contains(errStr2, "file exists") || strings.Contains(errStr2, "exists") {
						klog.V(2).InfoS("TC filter already exists (classifier mode); skipping add", "interface", ifaceName, "dir", direction, "protocol", fmt.Sprintf("0x%04x", proto), "priority", prio)
						added++
						prio++
						continue
					}
					klog.V(2).InfoS("Failed to add TC filter", "interface", ifaceName, "dir", direction, "protocol", fmt.Sprintf("0x%04x", proto), "priority", prio, "error", err)
				} else {
					added++
					prio++
					continue
				}
			} else {
				added++
				prio++
			}
		}
	}

	// Egress filters
	addFilters(netlink.HANDLE_MIN_EGRESS, "egress", "netscope_egress")
	// Ingress filters
	addFilters(netlink.HANDLE_MIN_INGRESS, "ingress", "netscope_ingress")

	if added == 0 {
		return fmt.Errorf("failed to add any TC filter to %s", ifaceName)
	}

	// We don't have a link.Link for netlink-based attachment, so we'll store nil
	// and handle cleanup differently
	klog.V(2).InfoS("Attached eBPF program via legacy TC", "interface", ifaceName, "filters", added)
	return nil
}

func (a *Agent) watchPods(ctx context.Context) error {
	// Create informer to watch only pods on this node
	fieldSelector := fields.OneTermEqualSelector("spec.nodeName", a.nodeName).String()
	informerFactory := informers.NewSharedInformerFactoryWithOptions(
		a.kubeClient,
		time.Minute,
		informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
			opts.FieldSelector = fieldSelector
		}),
	)

	podInformer := informerFactory.Core().V1().Pods().Informer()

	podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			a.handlePodAdd(pod)
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			pod := newObj.(*corev1.Pod)
			a.handlePodAdd(pod)
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			a.handlePodDelete(pod)
		},
	})

	informerFactory.Start(ctx.Done())

	// Wait for initial sync
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		return fmt.Errorf("failed to sync pod cache")
	}

	klog.InfoS("Started watching pods on node", "node", a.nodeName)
	return nil
}

func (a *Agent) handlePodAdd(pod *corev1.Pod) {
	if pod.Status.PodIP != "" && pod.Status.Phase == corev1.PodRunning {
		a.podIPs[pod.Status.PodIP] = true
		klog.V(3).InfoS("Added pod IP", "pod", pod.Name, "ip", pod.Status.PodIP)
	}
}

func (a *Agent) handlePodDelete(pod *corev1.Pod) {
	if pod.Status.PodIP != "" {
		delete(a.podIPs, pod.Status.PodIP)
		klog.V(3).InfoS("Removed pod IP", "pod", pod.Name, "ip", pod.Status.PodIP)
	}
}

func (a *Agent) collectAndSend() error {
	klog.V(8).InfoS("Collecting and sending traffic data", "links", a.links)
	// Read data from eBPF map
	data, err := a.readTrafficData()
	if err != nil {
		return fmt.Errorf("failed to read traffic data: %w", err)
	}

	klog.V(8).InfoS("Read traffic data", "entries", len(data))
	if len(data) == 0 {
		klog.V(4).InfoS("No traffic data to send")
		return nil
	}

	// Filter for traffic originating from pods on this node
	filteredData := a.filterLocalTraffic(data)
	if len(filteredData) == 0 {
		klog.V(4).InfoS("No local pod traffic to send")
		return nil
	}
	klog.V(8).InfoS("Filtered traffic data", "entries", len(filteredData))

	// Create payload
	p := &payload.Payload{
		NodeName: a.nodeName,
		Data:     filteredData,
	}

	// Encode and send
	encoded, err := p.Encode()
	if err != nil {
		return fmt.Errorf("failed to encode payload: %w", err)
	}

	if err := a.sendToServer(encoded); err != nil {
		return fmt.Errorf("failed to send to server: %w", err)
	}

	klog.V(8).InfoS("Sent traffic data", "entries", len(filteredData), "bytes", len(encoded))
	return nil
}

func (a *Agent) readTrafficData() (map[payload.IPKey]payload.IPValue, error) {
	result := make(map[payload.IPKey]payload.IPValue)

	var key netscopeIpKey
	var value netscopeIpValue

	iter := a.objs.IpTrafficMap.Iterate()
	for iter.Next(&key, &value) {
		ipKey := payload.IPKey{
			SrcIP: byteorder.ToNetwork32(key.SrcIp),
			DstIP: byteorder.ToNetwork32(key.DstIp),
		}
		ipValue := payload.IPValue{
			Bytes: value.Bytes,
		}
		result[ipKey] = ipValue

		// Delete the entry after reading (to avoid double-counting)
		if err := a.objs.IpTrafficMap.Delete(&key); err != nil {
			klog.V(3).InfoS("Failed to delete map entry", "error", err)
		}
	}

	if err := iter.Err(); err != nil {
		return nil, fmt.Errorf("failed to iterate over map: %w", err)
	}

	return result, nil
}

func (a *Agent) filterLocalTraffic(data map[payload.IPKey]payload.IPValue) map[payload.IPKey]payload.IPValue {
	filtered := make(map[payload.IPKey]payload.IPValue)

	for key, value := range data {
		srcIP := byteorder.Uint32ToIP(key.SrcIP).String()
		dstIP := byteorder.Uint32ToIP(key.DstIP).String()
		klog.V(3).InfoS("Filtering traffic", "srcIP", srcIP, "dstIP", dstIP)
		// Include traffic where either endpoint is a pod on this node (egress or ingress)
		if a.podIPs[srcIP] || a.podIPs[dstIP] {
			filtered[key] = value
		}
	}

	return filtered
}

func (a *Agent) sendToServer(data []byte) error {
	url := fmt.Sprintf("http://%s/api/v1/traffic", a.serverEndpoint)

	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		klog.ErrorS(err, "Failed to create request", "url", url)
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/octet-stream")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("server returned non-OK status: %d", resp.StatusCode)
	}

	return nil
}

func (a *Agent) cleanup() {
	klog.InfoS("Cleaning up agent resources")

	// Close all TCX links (these get auto-detached when link is closed)
	for _, l := range a.links {
		if err := l.Close(); err != nil {
			klog.ErrorS(err, "Failed to close link")
		}
	}

	// Best-effort removal of legacy TC filters we may have installed via netlink
	if err := a.cleanupLegacyTCFilters(); err != nil {
		klog.ErrorS(err, "Failed to cleanup legacy TC filters")
	}

	// Close eBPF objects
	if a.objs != nil {
		if err := a.objs.Close(); err != nil {
			klog.ErrorS(err, "Failed to close eBPF objects")
		}
	}
}

// cleanupLegacyTCFilters removes any lingering TC BPF filters that were added via the legacy
// TC path (clsact qdisc with bpf filters). It looks for filters with the names we used when
// attaching: "netscope_egress" and "netscope_ingress" and deletes them from
// both ingress and egress hooks on likely pod-facing interfaces (veth/eni/cali).
func (a *Agent) cleanupLegacyTCFilters() error {
	ifaces, err := net.Interfaces()
	if err != nil {
		return fmt.Errorf("failed to list interfaces: %w", err)
	}

	removed := 0
	for _, iface := range ifaces {
		name := iface.Name
		if !(strings.HasPrefix(name, "veth") || strings.HasPrefix(name, "eni") || strings.HasPrefix(name, "cali")) {
			continue
		}

		nlLink, err := netlink.LinkByName(name)
		if err != nil {
			klog.V(2).InfoS("Skipping interface; failed to get netlink link", "interface", name, "error", err)
			continue
		}

		for _, parent := range []uint32{netlink.HANDLE_MIN_INGRESS, netlink.HANDLE_MIN_EGRESS} {
			filters, err := netlink.FilterList(nlLink, parent)
			if err != nil {
				klog.V(2).InfoS("Failed to list TC filters", "interface", name, "parent", parent, "error", err)
				continue
			}
			for _, f := range filters {
				bf, ok := f.(*netlink.BpfFilter)
				if !ok {
					continue
				}
				if bf.Name == "netscope_egress" || bf.Name == "netscope_ingress" {
					if err := netlink.FilterDel(bf); err != nil {
						klog.V(1).InfoS("Failed to delete TC filter", "interface", name, "filter", bf.Name, "prio", bf.Priority, "protocol", fmt.Sprintf("0x%04x", bf.Protocol), "error", err)
					} else {
						removed++
						klog.V(2).InfoS("Deleted TC filter", "interface", name, "filter", bf.Name, "prio", bf.Priority, "protocol", fmt.Sprintf("0x%04x", bf.Protocol))
					}
				}
			}
		}
	}

	klog.InfoS("Legacy TC filter cleanup completed", "removed", removed)
	return nil
}
