package main

import (
	"context"
	"flag"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"syscall"
	"time"

	"k8s.io/klog/v2"

	"netscope/agent"
)

func main() {
	var (
		nodeName           string
		serverEndpoint     string
		collectionInterval time.Duration
		kubeconfig         string
		debugAddr          string
	)

	flag.StringVar(&nodeName, "node-name", os.Getenv("NODE_NAME"), "Name of the Kubernetes node this agent runs on")
	flag.StringVar(&serverEndpoint, "server-endpoint", "server:8080", "Address of the netscope server")
	flag.DurationVar(&collectionInterval, "collection-interval", 10*time.Second, "How often to collect and send data")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (for development)")
	flag.StringVar(&debugAddr, "debug-addr", "", "If set, start debug HTTP server (pprof) on this address, e.g. :6060")

	klog.InitFlags(nil)
	flag.Parse()

	if nodeName == "" {
		klog.ErrorS(nil, "node-name is required")
		os.Exit(1)
	}

	klog.InfoS("Starting netscope-agent",
		"version", "v0.1.0",
		"node", nodeName,
		"server", serverEndpoint,
		"interval", collectionInterval,
	)

	// Optionally start debug HTTP server (pprof + health)
	if debugAddr != "" {
		http.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("ok"))
		})
		go func() {
			klog.InfoS("Starting debug HTTP server", "addr", debugAddr)
			if err := http.ListenAndServe(debugAddr, nil); err != nil {
				klog.ErrorS(err, "Debug HTTP server exited")
			}
		}()
	}

	// Create agent
	ag, err := agent.NewAgent(agent.Config{
		NodeName:           nodeName,
		ServerEndpoint:     serverEndpoint,
		CollectionInterval: collectionInterval,
		KubeConfigPath:     kubeconfig,
	})
	if err != nil {
		klog.ErrorS(err, "Failed to create agent")
		os.Exit(1)
	}

	// Setup signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Run agent
	if err := ag.Run(ctx); err != nil {
		klog.ErrorS(err, "Agent failed")
		os.Exit(1)
	}

	klog.InfoS("Agent stopped gracefully")
}
