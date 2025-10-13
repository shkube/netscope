.PHONY: all generate build build-agent build-server docker docker-agent docker-server clean deploy

# Variables
GO := go
CLANG := clang
DOCKER := docker
KUBECTL := kubectl

# Image names
AGENT_IMAGE := netscope-agent:latest
SERVER_IMAGE := netscope-server:latest

# Build output directory
BUILD_DIR := bin

all: generate build

# Install bpf2go tool (required for generate)
install-bpf2go:
	@echo "Installing bpf2go..."
	$(GO) install github.com/cilium/ebpf/cmd/bpf2go@latest

# Generate eBPF Go bindings
generate: install-bpf2go
	@echo "Generating eBPF Go bindings..."
	cd agent && $(GO) generate

# Build all binaries
build: build-agent build-server

# Build agent binary
build-agent:
	@echo "Building agent..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/netscope-agent ./cmd/agent

# Build server binary
build-server:
	@echo "Building server..."
	@mkdir -p $(BUILD_DIR)
	$(GO) build -o $(BUILD_DIR)/netscope-server ./cmd/server

# Build all Docker images
docker: docker-agent docker-server

# Build agent Docker image
docker-agent:
	@echo "Building agent Docker image..."
	$(DOCKER) build -t $(AGENT_IMAGE) -f Dockerfile.agent .

# Build server Docker image
docker-server:
	@echo "Building server Docker image..."
	$(DOCKER) build -t $(SERVER_IMAGE) -f Dockerfile.server .

# Deploy to Kubernetes
deploy:
	@echo "Deploying to Kubernetes..."
	$(KUBECTL) apply -f deploy/netscope.yaml

# Undeploy from Kubernetes
undeploy:
	@echo "Removing from Kubernetes..."
	$(KUBECTL) delete -f deploy/netscope.yaml

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -rf $(BUILD_DIR)
	rm -f agent/*_bpfeb.go agent/*_bpfel.go
	rm -f agent/*_bpfeb.o agent/*_bpfel.o

# Run tests
test:
	$(GO) test -v ./...

# Download dependencies
deps:
	$(GO) mod download
	$(GO) mod tidy

# Format code
fmt:
	$(GO) fmt ./...

# Run linters
lint:
	golangci-lint run

# Help
help:
	@echo "Makefile for netscope"
	@echo ""
	@echo "Targets:"
	@echo "  all             - Generate eBPF bindings and build all binaries (default)"
	@echo "  install-bpf2go  - Install bpf2go tool (required for generate)"
	@echo "  generate        - Generate eBPF Go bindings from C code"
	@echo "  build           - Build all binaries"
	@echo "  build-agent     - Build agent binary"
	@echo "  build-server    - Build server binary"
	@echo "  docker          - Build all Docker images"
	@echo "  docker-agent    - Build agent Docker image"
	@echo "  docker-server   - Build server Docker image"
	@echo "  deploy          - Deploy to Kubernetes cluster"
	@echo "  undeploy        - Remove from Kubernetes cluster"
	@echo "  clean           - Remove build artifacts"
	@echo "  test            - Run tests"
	@echo "  deps            - Download and tidy dependencies"
	@echo "  fmt             - Format Go code"
	@echo "  lint            - Run linters"
	@echo "  help            - Show this help message"
