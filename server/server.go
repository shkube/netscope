package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"
	"sigs.k8s.io/yaml"

	"netscope/pkg/byteorder"
	"netscope/pkg/payload"
)

const (
	topologyZoneLabel = "topology.kubernetes.io/zone"
	customCMKeyYAML   = "endpoints.yaml"
	customCMKeyJSON   = "endpoints.json"
)

type Server struct {
	listenAddr string
	kubeClient *kubernetes.Clientset

	// In-memory caches
	mu          sync.RWMutex
	podsByIP    map[string]*PodInfo  // IP -> PodInfo
	nodesByName map[string]*NodeInfo // NodeName -> NodeInfo

	// Custom endpoint mappings
	customExact map[string]*CustomEndpoint // exact IP -> endpoint
	customCIDRs []cidrEntry                // CIDR ranges

	// Prometheus metrics
	crossZoneTraffic *prometheus.CounterVec
	networkTraffic   *prometheus.CounterVec

	// Flow logs
	enableFlowLogs           bool
	customEndpointsKey       string
	customEndpointsNamespace string
}

type PodInfo struct {
	Name      string
	Namespace string
	NodeName  string
}

type NodeInfo struct {
	Name string
	Zone string
}

type CustomEndpoint struct {
	Name      string
	Namespace string
	Zone      string
}

type customEntry struct {
	Name      string   `json:"name" yaml:"name"`
	Namespace string   `json:"namespace" yaml:"namespace"`
	Zone      string   `json:"zone" yaml:"zone"`
	IPs       []string `json:"ips" yaml:"ips"`
	CIDRs     []string `json:"cidrs" yaml:"cidrs"`
}

type customConfig struct {
	Endpoints []customEntry `json:"endpoints" yaml:"endpoints"`
}

type cidrEntry struct {
	net *net.IPNet
	ep  *CustomEndpoint
}

type FlowLog struct {
	Timestamp    time.Time `json:"timestamp"`
	SrcPod       string    `json:"src_pod"`
	SrcNamespace string    `json:"src_namespace"`
	SrcIP        string    `json:"src_ip"`
	SrcZone      string    `json:"src_zone"`
	DstPod       string    `json:"dst_pod"`
	DstNamespace string    `json:"dst_namespace"`
	DstIP        string    `json:"dst_ip"`
	DstZone      string    `json:"dst_zone"`
	Bytes        uint64    `json:"bytes"`
}

type Config struct {
	ListenAddr               string
	KubeConfigPath           string
	EnableFlowLogs           bool
	CustomEndpointKey        string
	CustomEndpointsNamespace string
}

func NewServer(cfg Config) (*Server, error) {
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

	// Create Prometheus metrics
	crossZoneTraffic := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pod_cross_zone_network_traffic_bytes_total",
			Help: "Total bytes of cross-zone network traffic between pods",
		},
		[]string{"src_pod", "src_namespace", "dst_pod", "dst_namespace", "src_zone", "dst_zone"},
	)
	// All pod-to-pod traffic (regardless of zone)
	networkTraffic := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "pod_network_traffic_bytes_total",
			Help: "Total bytes of pod-to-pod network traffic (all zones)",
		},
		[]string{"src_pod", "src_namespace", "dst_pod", "dst_namespace", "src_zone", "dst_zone"},
	)

	// Register metrics
	prometheus.MustRegister(crossZoneTraffic)
	prometheus.MustRegister(networkTraffic)

	return &Server{
		listenAddr:               cfg.ListenAddr,
		kubeClient:               kubeClient,
		podsByIP:                 make(map[string]*PodInfo),
		nodesByName:              make(map[string]*NodeInfo),
		customExact:              make(map[string]*CustomEndpoint),
		customCIDRs:              make([]cidrEntry, 0),
		crossZoneTraffic:         crossZoneTraffic,
		networkTraffic:           networkTraffic,
		enableFlowLogs:           cfg.EnableFlowLogs,
		customEndpointsKey:       cfg.CustomEndpointKey,
		customEndpointsNamespace: cfg.CustomEndpointsNamespace,
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	klog.InfoS("Starting netscope server", "listen", s.listenAddr)

	// Start watching Kubernetes resources
	if err := s.watchKubernetesResources(ctx); err != nil {
		return fmt.Errorf("failed to start watching Kubernetes resources: %w", err)
	}

	// Start background refresher for custom endpoints
	s.startCustomEndpointsRefresher(ctx)

	// Setup HTTP server
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/traffic", s.handleTraffic)
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, err := w.Write([]byte("ok"))
		if err != nil {
			return
		}
	})

	server := &http.Server{
		Addr:         s.listenAddr,
		Handler:      mux,
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	errCh := make(chan error, 1)
	go func() {
		klog.InfoS("HTTP server listening", "address", s.listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// Wait for shutdown signal or error
	select {
	case <-ctx.Done():
		klog.InfoS("Shutting down server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return server.Shutdown(shutdownCtx)
	case err := <-errCh:
		return err
	}
}

func (s *Server) startCustomEndpointsRefresher(ctx context.Context) {
	// Initial load
	if err := s.refreshCustomEndpointsOnce(ctx); err != nil {
		klog.V(2).InfoS("Custom endpoints initial load failed", "error", err)
	}
	// Periodic refresh
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := s.refreshCustomEndpointsOnce(ctx); err != nil {
					klog.V(2).InfoS("Custom endpoints refresh failed", "error", err)
				}
			}
		}
	}()
}

func (s *Server) refreshCustomEndpointsOnce(ctx context.Context) error {
	cm, err := s.kubeClient.CoreV1().ConfigMaps(s.customEndpointsNamespace).Get(ctx, s.customEndpointsKey, metav1.GetOptions{})
	if err != nil {
		// If not found or other errors, just log and continue with existing mappings
		return fmt.Errorf("failed to get ConfigMap %s/%s: %w", s.customEndpointsNamespace, s.customEndpointsKey, err)
	}

	var raw string
	if cm.Data != nil {
		if v, ok := cm.Data[customCMKeyYAML]; ok {
			raw = v
		} else if v, ok := cm.Data[customCMKeyJSON]; ok {
			raw = v
		} else if v, ok := cm.Data["endpoints"]; ok {
			// fallback key
			raw = v
		}
	}
	if raw == "" {
		// No data; clear mappings
		s.mu.Lock()
		s.customExact = make(map[string]*CustomEndpoint)
		s.customCIDRs = nil
		s.mu.Unlock()
		klog.V(3).InfoS("Custom endpoints config empty; cleared mappings")
		return nil
	}

	cfg := &customConfig{}
	if err := yaml.Unmarshal([]byte(raw), cfg); err != nil {
		return fmt.Errorf("failed to parse custom endpoints config: %w", err)
	}

	newExact := make(map[string]*CustomEndpoint)
	newCIDRs := make([]cidrEntry, 0)

	for _, e := range cfg.Endpoints {
		if e.Name == "" {
			klog.V(2).InfoS("Skipping custom endpoint without name")
			continue
		}
		// default namespace if omitted
		ns := e.Namespace
		if ns == "" {
			ns = "external"
		}
		zone := e.Zone

		ep := &CustomEndpoint{Name: e.Name, Namespace: ns, Zone: zone}

		for _, ipStr := range e.IPs {
			ip := net.ParseIP(ipStr)
			if ip == nil || ip.To4() == nil {
				klog.V(2).InfoS("Invalid custom endpoint IP; skipping", "ip", ipStr, "name", e.Name)
				continue
			}
			newExact[ip.To4().String()] = ep
		}
		for _, cidrStr := range e.CIDRs {
			_, n, err := net.ParseCIDR(cidrStr)
			if err != nil {
				klog.V(2).InfoS("Invalid custom endpoint CIDR; skipping", "cidr", cidrStr, "name", e.Name, "error", err)
				continue
			}
			newCIDRs = append(newCIDRs, cidrEntry{net: n, ep: ep})
		}
	}

	s.mu.Lock()
	s.customExact = newExact
	s.customCIDRs = newCIDRs
	s.mu.Unlock()

	klog.V(2).InfoS("Loaded custom endpoints", "exact", len(newExact), "cidrs", len(newCIDRs))
	return nil
}

func (s *Server) lookupCustom(ip string) *CustomEndpoint {
	if ep, ok := s.customExact[ip]; ok {
		return ep
	}
	ipp := net.ParseIP(ip)
	if ipp == nil {
		return nil
	}
	for _, c := range s.customCIDRs {
		if c.net.Contains(ipp) {
			return c.ep
		}
	}
	return nil
}

func (s *Server) watchKubernetesResources(ctx context.Context) error {
	informerFactory := informers.NewSharedInformerFactory(s.kubeClient, time.Minute)

	// Watch pods
	podInformer := informerFactory.Core().V1().Pods().Informer()
	_, err := podInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			s.handlePodAddOrUpdate(obj.(*corev1.Pod))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			s.handlePodAddOrUpdate(newObj.(*corev1.Pod))
		},
		DeleteFunc: func(obj interface{}) {
			s.handlePodDelete(obj.(*corev1.Pod))
		},
	})
	if err != nil {
		return err
	}

	// Watch nodes
	nodeInformer := informerFactory.Core().V1().Nodes().Informer()
	_, err = nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			s.handleNodeAddOrUpdate(obj.(*corev1.Node))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			s.handleNodeAddOrUpdate(newObj.(*corev1.Node))
		},
		DeleteFunc: func(obj interface{}) {
			s.handleNodeDelete(obj.(*corev1.Node))
		},
	})
	if err != nil {
		return err
	}

	informerFactory.Start(ctx.Done())

	// Wait for caches to sync
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced, nodeInformer.HasSynced) {
		return fmt.Errorf("failed to sync caches")
	}

	klog.InfoS("Kubernetes resource watchers started")
	return nil
}

func (s *Server) handlePodAddOrUpdate(pod *corev1.Pod) {
	if pod.Status.PodIP == "" || pod.Status.Phase != corev1.PodRunning {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.podsByIP[pod.Status.PodIP] = &PodInfo{
		Name:      pod.Name,
		Namespace: pod.Namespace,
		NodeName:  pod.Spec.NodeName,
	}

	klog.V(3).InfoS("Updated pod mapping", "pod", pod.Name, "ip", pod.Status.PodIP, "node", pod.Spec.NodeName)
}

func (s *Server) handlePodDelete(pod *corev1.Pod) {
	if pod.Status.PodIP == "" {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.podsByIP, pod.Status.PodIP)
	klog.V(3).InfoS("Deleted pod mapping", "pod", pod.Name, "ip", pod.Status.PodIP)
}

func (s *Server) handleNodeAddOrUpdate(node *corev1.Node) {
	zone := node.Labels[topologyZoneLabel]
	if zone == "" {
		// Fallback to deprecated label
		zone = node.Labels["failure-domain.beta.kubernetes.io/zone"]
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.nodesByName[node.Name] = &NodeInfo{
		Name: node.Name,
		Zone: zone,
	}

	klog.V(3).InfoS("Updated node mapping", "node", node.Name, "zone", zone)
}

func (s *Server) handleNodeDelete(node *corev1.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.nodesByName, node.Name)
	klog.V(3).InfoS("Deleted node mapping", "node", node.Name)
}

func (s *Server) handleTraffic(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Read payload
	body, err := io.ReadAll(r.Body)
	if err != nil {
		klog.ErrorS(err, "Failed to read request body")
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	// Decode payload
	p, err := payload.Decode(body)
	if err != nil {
		klog.ErrorS(err, "Failed to decode payload")
		http.Error(w, "Failed to decode payload", http.StatusBadRequest)
		return
	}

	klog.V(8).InfoS("Received traffic data", "node", p.NodeName, "entries", len(p.Data))

	// Process traffic data
	s.processTrafficData(p)

	w.WriteHeader(http.StatusOK)
}

func (s *Server) processTrafficData(p *payload.Payload) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for key, value := range p.Data {
		srcIP := byteorder.Uint32ToIP(key.SrcIP).String()
		dstIP := byteorder.Uint32ToIP(key.DstIP).String()

		// Look up pod information first
		srcPod := s.podsByIP[srcIP]
		dstPod := s.podsByIP[dstIP]

		// Resolve identities: pod or custom endpoint
		var srcName, srcNs, srcZone string
		var dstName, dstNs, dstZone string

		if srcPod != nil {
			srcName, srcNs = srcPod.Name, srcPod.Namespace
			if srcNode := s.nodesByName[srcPod.NodeName]; srcNode != nil && srcNode.Zone != "" {
				srcZone = srcNode.Zone
			} else {
				srcZone = "unknown"
			}
		} else if ep := s.lookupCustom(srcIP); ep != nil {
			srcName, srcNs = ep.Name, ep.Namespace
			if ep.Zone != "" {
				srcZone = ep.Zone
			} else {
				srcZone = "unknown"
			}
		} else {
			klog.V(4).InfoS("Skipping traffic - source not found", "srcIP", srcIP)
			continue
		}

		if dstPod != nil {
			dstName, dstNs = dstPod.Name, dstPod.Namespace
			if dstNode := s.nodesByName[dstPod.NodeName]; dstNode != nil && dstNode.Zone != "" {
				dstZone = dstNode.Zone
			} else {
				dstZone = "unknown"
			}
		} else if ep := s.lookupCustom(dstIP); ep != nil {
			dstName, dstNs = ep.Name, ep.Namespace
			if ep.Zone != "" {
				dstZone = ep.Zone
			} else {
				dstZone = "unknown"
			}
		} else {
			klog.V(4).InfoS("Skipping traffic - destination not found", "dstIP", dstIP)
			continue
		}

		// Always record total traffic (pod or custom endpoints)
		s.networkTraffic.WithLabelValues(
			srcName,
			srcNs,
			dstName,
			dstNs,
			srcZone,
			dstZone,
		).Add(float64(value.Bytes))

		// Record cross-zone traffic only when zones are known and differ
		if srcZone != "unknown" && dstZone != "unknown" && srcZone != dstZone {
			s.crossZoneTraffic.WithLabelValues(
				srcName,
				srcNs,
				dstName,
				dstNs,
				srcZone,
				dstZone,
			).Add(float64(value.Bytes))

			// Log flow if enabled (log cross-zone only to reduce noise)
			if s.enableFlowLogs {
				flowLog := FlowLog{
					Timestamp:    time.Now(),
					SrcPod:       srcName,
					SrcNamespace: srcNs,
					SrcIP:        srcIP,
					SrcZone:      srcZone,
					DstPod:       dstName,
					DstNamespace: dstNs,
					DstIP:        dstIP,
					DstZone:      dstZone,
					Bytes:        value.Bytes,
				}

				logJSON, _ := json.Marshal(flowLog)
				klog.InfoS("Flow", "data", string(logJSON))
			}

			klog.V(3).InfoS("Recorded cross-zone traffic",
				"src", srcName,
				"dst", dstName,
				"srcZone", srcZone,
				"dstZone", dstZone,
				"bytes", value.Bytes,
			)
		}
	}
}
