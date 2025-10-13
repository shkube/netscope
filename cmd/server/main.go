package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"k8s.io/klog/v2"

	"netscope/server"
)

func main() {
	var (
		listenAddr                 string
		kubeconfig                 string
		enableFlowLogs             bool
		customEndpointsCMKey       string
		customEndpointsCMNamespace string
	)

	flag.StringVar(&listenAddr, "listen-addr", ":8080", "Address to listen on")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file (for development)")
	flag.BoolVar(&enableFlowLogs, "enable-flow-logs", false, "Enable flow logging to stdout")
	flag.StringVar(&customEndpointsCMKey, "custom-endpoints-key", "netscope-custom-endpoints", "Custom endpoints configmap key")
	flag.StringVar(&customEndpointsCMNamespace, "custom-endpoints-namespace", "netscope", "Custom endpoints configmap namespace")

	klog.InitFlags(nil)
	flag.Parse()

	klog.InfoS("Starting netscope-server",
		"version", "v0.1.0",
		"listen", listenAddr,
		"flowLogs", enableFlowLogs,
		"customEndpointsCMKey", customEndpointsCMKey,
		"customEndpointsCMNamespace", customEndpointsCMNamespace,
	)

	// Create server
	srv, err := server.NewServer(server.Config{
		ListenAddr:               listenAddr,
		KubeConfigPath:           kubeconfig,
		EnableFlowLogs:           enableFlowLogs,
		CustomEndpointKey:        customEndpointsCMKey,
		CustomEndpointsNamespace: customEndpointsCMNamespace,
	})
	if err != nil {
		klog.ErrorS(err, "Failed to create server")
		os.Exit(1)
	}

	// Setup signal handling
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Run server
	if err := srv.Run(ctx); err != nil {
		klog.ErrorS(err, "Server failed")
		os.Exit(1)
	}

	klog.InfoS("Server stopped gracefully")
}
