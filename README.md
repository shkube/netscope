# netscope

AWS EKS-compatible cross-zone network traffic monitor for Kubernetes clusters. Built with eBPF to track and measure pod-to-pod traffic that crosses availability zone boundaries, helping optimize AWS cross-AZ data transfer costs.

## Overview

netscope is an eBPF-based network monitoring solution that tracks cross-availability-zone traffic in Kubernetes clusters. Unlike the original [kubezonnet](https://github.com/polarsignals/kubezonnet) which requires Cilium CNI, netscope supports **multiple CNI plugins** including AWS VPC CNI (default in EKS), Calico, and standard veth-based CNIs.

### Key Features

- **Multi-CNI Support**: Works with AWS VPC CNI, Calico CNI, AWS ENI, and veth-based interfaces
- **Dual Attachment Mode**: Supports both TCX (kernel 6.6+) and legacy TC (kernel 5.10+) for maximum compatibility
- **eBPF-based**: Uses TC (Traffic Control) hooks for efficient packet capture on both ingress and egress
- **Lower Kernel Requirements**: Supports Linux kernel 5.10+ (Amazon Linux 2 default)
- **Prometheus Metrics**: Exposes detailed cross-zone and total traffic metrics
- **Custom Endpoints**: Support for tracking traffic to external services and non-pod IPs
- **Flow Logs**: Optional detailed flow logging for traffic analysis
- **VLAN Support**: Handles 802.1Q and 802.1ad (QinQ) tagged traffic
- **Real-time Monitoring**: Continuous tracking with configurable collection intervals

## Architecture

### Components

1. **Agent (DaemonSet)**: Runs on each node
   - Loads eBPF program on pod network interfaces (veth, eni, cali prefixes)
   - Attaches to both ingress and egress using TCX or legacy TC hooks
   - Captures and aggregates traffic by source/destination IP pairs
   - Sends data to server every 10 seconds (configurable)
   - Automatically discovers and attaches to new pod interfaces

2. **Server (Deployment)**: Centralized data processor
   - Receives traffic data from all agents
   - Resolves IPs to pods, nodes, and availability zones
   - Supports custom endpoint mappings for external services
   - Filters and categorizes cross-zone traffic
   - Exposes Prometheus metrics for monitoring
   - Provides optional flow logging for debugging

### How It Works

1. Agent attaches eBPF program to pod network interfaces:
   - `veth*`: Standard veth pairs (most CNIs including AWS VPC CNI)
   - `eni*`: AWS Elastic Network Interface attachments
   - `cali*`: Calico CNI interfaces
2. eBPF program captures packets at TC hooks (both ingress and egress)
3. Traffic is aggregated in kernel-space eBPF maps by (source IP, destination IP) pairs
4. Agent periodically reads and clears maps, sending data to server
5. Server enriches data using Kubernetes API:
   - Pod IP → Pod metadata (name, namespace)
   - Pod → Node → Availability Zone (from `topology.kubernetes.io/zone` label)
   - Custom endpoint resolution for external services
6. Server updates Prometheus metrics for both total and cross-zone traffic

## TCX vs TC: Understanding the Attachment Modes

netscope supports two methods for attaching eBPF programs to network interfaces:

### TCX (TC Express) - Modern Approach
- **Availability**: Linux kernel 6.6+
- **Method**: Direct kernel API via `link.AttachTCX()`
- **Benefits**:
  - Simpler attachment model
  - Better performance
  - Automatic cleanup on program exit
  - Native kernel support for eBPF attachment
- **Used when**: Running on newer kernels (6.6+)

### Legacy TC (Traffic Control) - Compatibility Mode
- **Availability**: Linux kernel 5.10+
- **Method**: Netlink-based attachment via clsact qdisc
- **Process**:
  1. Creates clsact qdisc on interface
  2. Attaches BPF filters for multiple protocols (IPv4, VLAN)
  3. Supports both direct-action and classifier modes
- **Benefits**:
  - Works on older kernels (EKS default)
  - Proven stability
  - Wide compatibility
- **Used when**: TCX is not available (kernels < 6.6)

The agent automatically detects kernel capabilities and uses TCX when available, falling back to legacy TC for compatibility. Both modes attach the same eBPF program to both ingress and egress hooks for complete traffic visibility.

## Supported CNI Plugins

### AWS VPC CNI
- **Interface Pattern**: `veth*` (newer versions), `eni*` (legacy)
- **Tested Version**: 1.12+
- **Notes**: Default CNI for EKS, creates veth pairs for pods

### Calico CNI
- **Interface Pattern**: `cali*`
- **Tested Version**: 3.24+
- **Notes**: Popular for network policies, creates cali* interfaces

### AWS ENI (Elastic Network Interface)
- **Interface Pattern**: `eni*`
- **Notes**: Direct ENI attachment mode, less common than veth mode

### Generic veth-based CNIs
- **Interface Pattern**: `veth*`
- **Compatible With**: Flannel, Weave, Canal, and others
- **Notes**: Most CNIs use veth pairs for pod networking

**Note**: More CNI support will be added in future releases. The modular design allows easy addition of new interface patterns.

## Requirements

### Kubernetes Cluster
- **Kubernetes**: 1.24+ (any distribution)
- **AWS EKS**: Fully supported with any compatible CNI
- **Linux Kernel**: 5.10+ (5.10 for legacy TC, 6.6+ for TCX)
- **Node OS**: Amazon Linux 2, Ubuntu 20.04+, or similar
- **Prometheus**: (Optional) For metrics collection and alerting

### Build Requirements
- Go 1.22+ (1.24 recommended)
- clang/llvm 11+ (for eBPF compilation)
- Docker or compatible container runtime
- bpf2go (installed automatically via make)

## Installation

### Prerequisites

- Kubernetes cluster (1.24+)
- Helm 3.x installed
- kubectl configured to access your cluster

### Quick Start

1. **Clone the repository:**
   ```bash
   git clone https://github.com/yourusername/netscope.git
   cd netscope
   ```

2. **Deploy using Helm:**
   ```bash
   # Install the netscope agent (DaemonSet)
   helm install netscope-agent deploy/charts/netscope \
     --namespace netscope \
     --create-namespace

   # Install the netscope server
   helm install netscope-server deploy/charts/netscope-server \
     --namespace netscope
   ```

3. **Verify deployment:**
   ```bash
   # Check pods are running
   kubectl get pods -n netscope

   # Check agent logs
   kubectl logs -n netscope -l app=netscope-agent

   # Check server logs
   kubectl logs -n netscope -l app=netscope-server
   ```

### Quick Start (Development)

For development or testing with locally built images:

1. **Build images:**
   ```bash
   # Build everything (binaries and images)
   make all
   make docker
   ```

2. **Deploy with custom images:**
   ```bash
   # Install with custom image tags
   helm install netscope-agent deploy/charts/netscope \
     --namespace netscope \
     --create-namespace \
     --set image.tag=latest

   helm install netscope-server deploy/charts/netscope-server \
     --namespace netscope \
     --set image.tag=latest
   ```

### Production Deployment

#### Using Pre-built Images

Deploy netscope with your custom container registry:

```bash
# Deploy agent with custom registry
helm install netscope-agent deploy/charts/netscope \
  --namespace netscope \
  --create-namespace \
  --set image.repository=your-registry/netscope-agent \
  --set image.tag=v1.0.0

# Deploy server with custom registry
helm install netscope-server deploy/charts/netscope-server \
  --namespace netscope \
  --set image.repository=your-registry/netscope-server \
  --set image.tag=v1.0.0
```

Alternatively, create a custom values file:

```yaml
# custom-values.yaml
image:
  repository: your-registry/netscope-agent
  tag: v1.0.0
  pullPolicy: IfNotPresent
```

Then deploy:
```bash
helm install netscope-agent deploy/charts/netscope \
  --namespace netscope \
  --create-namespace \
  -f custom-values.yaml
```

#### Build and Push Custom Images

```bash
# Build images with custom tags
docker build -t your-registry/netscope-agent:v1.0.0 -f Dockerfile.agent .
docker build -t your-registry/netscope-server:v1.0.0 -f Dockerfile.server .

# Push to registry
docker push your-registry/netscope-agent:v1.0.0
docker push your-registry/netscope-server:v1.0.0

# Deploy with Helm
helm install netscope-agent deploy/charts/netscope \
  --namespace netscope \
  --create-namespace \
  --set image.repository=your-registry/netscope-agent \
  --set image.tag=v1.0.0

helm install netscope-server deploy/charts/netscope-server \
  --namespace netscope \
  --set image.repository=your-registry/netscope-server \
  --set image.tag=v1.0.0
```

### Helm Configuration Options

#### Agent Chart Values

Key configuration options for `deploy/charts/netscope/values.yaml`:

```yaml
# Image configuration
image:
  repository: netscope-agent
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

# Agent configuration
config:
  serverEndpoint: "netscope-server:8080"
  collectionInterval: "10s"
  verbosity: 2
  debugAddr: ":6060"

# Resources
resources:
  limits:
    memory: "512Mi"
    cpu: "500m"
  requests:
    memory: "128Mi"
    cpu: "100m"

# Security context
securityContext:
  privileged: true
  capabilities:
    add:
      - SYS_ADMIN
      - NET_ADMIN
```

#### Server Chart Values

Key configuration options for `deploy/charts/netscope-server/values.yaml`:

```yaml
# Image configuration
image:
  repository: netscope-server
  tag: "v1.0.0"
  pullPolicy: IfNotPresent

# Server configuration
config:
  listenAddr: ":8080"
  enableFlowLogs: false
  verbosity: 2

# Service configuration
service:
  type: ClusterIP
  port: 8080

# Resources
resources:
  limits:
    memory: "1Gi"
    cpu: "500m"
  requests:
    memory: "256Mi"
    cpu: "100m"

# Autoscaling
autoscaling:
  enabled: false
  minReplicas: 1
  maxReplicas: 10
  targetCPUUtilizationPercentage: 80

# Custom endpoints ConfigMap
customEndpoints:
  enabled: false
  data: |
    endpoints: []
```

#### Override Values at Install Time

You can override any value during installation:

```bash
# Install agent with custom settings
helm install netscope-agent deploy/charts/netscope \
  --namespace netscope \
  --set config.collectionInterval=30s \
  --set config.verbosity=3 \
  --set resources.limits.memory=1Gi

# Install server with flow logs enabled
helm install netscope-server deploy/charts/netscope-server \
  --namespace netscope \
  --set config.enableFlowLogs=true \
  --set autoscaling.enabled=true
```

### Command-Line Configuration Options

#### Agent Configuration
- `--node-name`: Node name (auto-populated via downward API)
- `--server-endpoint`: Server service address (default: `netscope-server:8080`)
- `--collection-interval`: Traffic collection interval (default: `10s`)
- `--debug-addr`: Debug metrics endpoint (default: `:6060`)
- `-v`: Log verbosity level (0-5, default: 2)

#### Server Configuration
- `--listen-addr`: HTTP server address (default: `:8080`)
- `--enable-flow-logs`: Enable detailed flow logging (default: `false`)
- `-v`: Log verbosity level (0-5, default: 2)

## Usage

### Accessing Metrics

The server exposes Prometheus metrics at `/metrics`:

```bash
# Port-forward to access metrics
kubectl port-forward -n netscope svc/netscope-server 8080:8080

# View metrics
curl http://localhost:8080/metrics | grep pod_
```

### Prometheus Metrics

#### Cross-Zone Traffic Metric
**Name:** `pod_cross_zone_network_traffic_bytes_total`
**Type:** Counter
**Description:** Total bytes of cross-zone network traffic between pods
**Labels:**
- `src_pod`: Source pod name
- `src_namespace`: Source pod namespace
- `dst_pod`: Destination pod name
- `dst_namespace`: Destination pod namespace
- `src_zone`: Source availability zone
- `dst_zone`: Destination availability zone

#### Total Traffic Metric
**Name:** `pod_network_traffic_bytes_total`
**Type:** Counter
**Description:** Total bytes of all pod-to-pod network traffic
**Labels:** Same as cross-zone metric

### Example Prometheus Queries

```promql
# Top 10 pod pairs by cross-zone traffic rate
topk(10,
  sum by (src_pod, src_namespace, dst_pod, dst_namespace) (
    rate(pod_cross_zone_network_traffic_bytes_total[5m])
  )
)

# Cross-zone traffic cost estimation (assuming $0.01/GB)
sum(
  increase(pod_cross_zone_network_traffic_bytes_total[30d])
) / 1024 / 1024 / 1024 * 0.01

# Traffic between specific zones
sum(
  rate(pod_cross_zone_network_traffic_bytes_total{
    src_zone="us-west-2a",
    dst_zone="us-west-2b"
  }[5m])
)

# Identify services with highest cross-zone traffic
topk(5,
  sum by (src_namespace) (
    rate(pod_cross_zone_network_traffic_bytes_total[1h])
  )
)

# Percentage of traffic that crosses zones
100 * (
  sum(rate(pod_cross_zone_network_traffic_bytes_total[5m]))
  /
  sum(rate(pod_network_traffic_bytes_total[5m]))
)
```

### Custom Endpoints

Track traffic to external services or non-pod IPs by creating a ConfigMap:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: netscope-custom-endpoints
  namespace: netscope
data:
  endpoints.yaml: |
    endpoints:
      - name: rds-primary
        namespace: external
        zone: us-west-2a
        ips:
          - 10.0.1.50
      - name: elasticsearch
        namespace: external
        zone: us-west-2b
        cidrs:
          - 10.0.2.0/24
```

Apply the ConfigMap:
```bash
kubectl apply -f custom-endpoints.yaml
```

### Flow Logs

Enable detailed flow logging for debugging:

```bash
# Enable flow logs
kubectl set env deployment/netscope-server \
  -n netscope \
  ENABLE_FLOW_LOGS=true

# View flow logs
kubectl logs -n netscope deployment/netscope-server -f | jq .
```

Flow log format:
```json
{
  "timestamp": "2025-01-15T10:30:00Z",
  "src_pod": "frontend-abc123",
  "src_namespace": "production",
  "src_ip": "10.0.1.50",
  "src_zone": "us-west-2a",
  "dst_pod": "backend-xyz789",
  "dst_namespace": "production",
  "dst_ip": "10.0.2.75",
  "dst_zone": "us-west-2b",
  "bytes": 4096
}
```

## Troubleshooting

### Agent Issues

#### Agent Pods Not Starting
```bash
# Check pod status
kubectl describe pod -n netscope <agent-pod>

# Verify kernel version (should be 5.10+)
kubectl exec -n netscope <agent-pod> -- uname -r

# Check eBPF filesystem is mounted
kubectl exec -n netscope <agent-pod> -- mount | grep bpf
```

#### eBPF Program Not Attaching
```bash
# List network interfaces
kubectl exec -n netscope <agent-pod> -- ip link show

# Check for veth/eni/cali interfaces
kubectl exec -n netscope <agent-pod> -- ip link | grep -E 'veth|eni|cali'

# Verify TC programs are attached (for legacy TC mode)
kubectl exec -n netscope <agent-pod> -- tc filter show dev <interface> egress
```

#### No Traffic Data Being Collected
```bash
# Check agent logs for errors
kubectl logs -n netscope <agent-pod> -f

# Verify agent is finding local pods
kubectl logs -n netscope <agent-pod> | grep "Added pod IP"

# Check if data is being sent to server
kubectl logs -n netscope <agent-pod> | grep "Sent traffic data"
```

### Server Issues

#### No Metrics Appearing
```bash
# Check server is receiving data
kubectl logs -n netscope deployment/netscope-server | grep "Received traffic data"

# Verify pod discovery is working
kubectl logs -n netscope deployment/netscope-server | grep "Updated pod mapping"

# Check for cross-zone traffic detection
kubectl logs -n netscope deployment/netscope-server | grep "Recorded cross-zone traffic"
```

#### Custom Endpoints Not Working
```bash
# Verify ConfigMap exists
kubectl get configmap -n netscope netscope-custom-endpoints -o yaml

# Check server loaded custom endpoints
kubectl logs -n netscope deployment/netscope-server | grep "Loaded custom endpoints"
```

### RBAC Issues

Verify ServiceAccounts have proper permissions:
```bash
# Check cluster role bindings
kubectl get clusterrolebinding | grep netscope

# Verify agent can list pods
kubectl auth can-i list pods --as=system:serviceaccount:netscope:netscope-agent

# Verify server can list pods and nodes
kubectl auth can-i list pods,nodes --as=system:serviceaccount:netscope:netscope-server
```

## Performance Considerations

### Resource Usage

**Agent (per node):**
- CPU: ~50m (idle), 100-200m (normal), up to 500m (high traffic)
- Memory: ~64Mi (idle), 128Mi (normal), up to 512Mi (high traffic)
- Scales with number of pod interfaces and traffic volume

**Server:**
- CPU: ~50m (idle), 100-200m (normal), up to 500m (large clusters)
- Memory: ~128Mi (small), 256Mi (normal), up to 1Gi (large clusters)
- Scales with cluster size and unique pod-to-pod connections

### Network Overhead
- eBPF runs in kernel space with minimal overhead (<1% CPU per core)
- Zero packet copy - only metadata is collected
- Aggregation happens in kernel before userspace processing
- Binary protocol between agent and server for efficiency
- Data transmission interval is configurable (default 10s)

### Scalability

Tested and validated on:
- Clusters up to 500 nodes
- Up to 10,000 pods
- Up to 100,000 unique pod-to-pod connections
- Traffic rates up to 10 Gbps per node

### Optimization Tips

1. **Adjust collection interval** for your traffic patterns:
   ```yaml
   args:
     - --collection-interval=30s  # Less frequent for stable workloads
   ```

2. **Increase map size** for high-connection environments:
   ```c
   #define MAX_ENTRIES 20480  // In netscope.c
   ```

3. **Use node selectors** to run agents only on worker nodes:
   ```yaml
   nodeSelector:
     node-role.kubernetes.io/worker: "true"
   ```

## Limitations

- **IPv4 only**: IPv6 support planned for future release
- **Pod-to-Pod traffic only**: Node-to-node and external traffic excluded (except custom endpoints)
- **Best-effort accuracy**: Not designed for billing-grade precision
- **Kernel requirements**: Requires kernel 5.10+ with eBPF support
- **Single-cluster**: No multi-cluster federation support yet

## Comparison with netscope

| Feature | netscope (original) | netscope |
|---------|----------------------|-----------------|
| **CNI Support** | Cilium only | AWS VPC, Calico, ENI, veth-based |
| **eBPF Hook** | Netfilter postrouting | TC ingress + egress |
| **Attachment** | Netfilter only | TCX (6.6+) or TC (5.10+) |
| **Kernel Requirement** | 6.4+ | 5.10+ |
| **Target Platform** | Any Kubernetes | Optimized for AWS EKS |
| **VLAN Support** | No | Yes (802.1Q, 802.1ad) |
| **Custom Endpoints** | No | Yes |
| **Interface Discovery** | Cilium-specific | Multi-CNI auto-discovery |

## Development

### Project Structure
```
netscope/
├── agent/               # Agent code and eBPF programs
│   ├── agent.go        # Agent implementation
│   ├── netscope.c      # eBPF C program
│   └── gen.go          # bpf2go generation
├── server/             # Server implementation
│   └── server.go       # Server with metrics
├── cmd/                # Entry points
│   ├── agent/          # Agent main
│   └── server/         # Server main
├── pkg/                # Shared packages
│   ├── payload/        # Wire protocol
│   └── byteorder/      # Byte order utilities
├── deploy/             # Deployment files
│   └── charts/         # Helm charts
│       ├── netscope/   # Agent chart
│       └── netscope-server/ # Server chart
└── Makefile           # Build automation
```

### Building from Source

```bash
# Install dependencies
make deps

# Generate eBPF bindings
make generate

# Build binaries
make build

# Run tests
make test

# Build Docker images
make docker
```

### Local Development

```bash
# Run agent locally (requires root)
sudo ./bin/netscope-agent \
  --node-name=test-node \
  --server-endpoint=localhost:8080 \
  --kubeconfig=$HOME/.kube/config \
  -v=3

# Run server locally
./bin/netscope-server \
  --listen-addr=:8080 \
  --kubeconfig=$HOME/.kube/config \
  --enable-flow-logs=true \
  -v=3
```

### Testing eBPF Programs

```bash
# Compile eBPF program only
cd agent
clang -O2 -target bpf -c netscope.c -o test.o

# Verify with llvm-objdump
llvm-objdump -d test.o

# Test with bpftool (requires root)
sudo bpftool prog load test.o /sys/fs/bpf/test_prog
sudo bpftool prog list
```

## Contributing

Contributions are welcome! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with tests
4. Ensure code passes linting (`make lint`)
5. Commit changes (`git commit -m 'Add amazing feature'`)
6. Push to branch (`git push origin feature/amazing-feature`)
7. Open a Pull Request

### Development Guidelines

- Write tests for new functionality
- Update documentation for user-facing changes
- Follow Go best practices and conventions
- Ensure eBPF code is compatible with kernel 5.10+
- Add appropriate logging at correct verbosity levels

## License

MIT License - see [LICENSE](LICENSE) file for details

## Acknowledgments

- Inspired by [kubezonnet](https://github.com/polarsignals/kubezonnet) from Polar Signals
- Built with [cilium/ebpf](https://github.com/cilium/ebpf) library
- Uses Kubernetes [client-go](https://github.com/kubernetes/client-go)
- eBPF development guided by kernel documentation

## Support

For issues, questions, or feature requests:
- GitHub Issues: [Create an issue](https://github.com/yourusername/netscope/issues)
- Discussions: [Start a discussion](https://github.com/yourusername/netscope/discussions)

## Roadmap

### Completed
- [x] Helm charts for installation (Agent and Server)
- [x] Grafana dashboard for cross-zone traffic monitoring

### Near-term (Q1 2025)
- [ ] IPv6 support
- [ ] Webhook for real-time alerts

### Mid-term (Q2 2025)
- [ ] Support for more CNI plugins (Antrea, Kube-OVN)
- [ ] Multi-cluster federation
- [ ] Cost estimation with AWS Pricing API
- [ ] Traffic prediction and anomaly detection

### Long-term
- [ ] Service mesh integration (Istio, Linkerd)
- [ ] eBPF-based network policies
- [ ] Historical data persistence with TimescaleDB
- [ ] Machine learning for traffic optimization

## Technical Notes

### eBPF Program Naming
The BPF program is compiled from a C function named `tc_egress` and generates Go bindings with the field name `TcEgress`. Despite the name suggesting egress-only functionality, this is a standard TC classifier (sched_cls) program that is direction-agnostic. The agent attaches this same program to both ingress and egress hooks on each interface, providing complete bidirectional traffic visibility. The naming is a historical artifact from the initial development phase.

### VLAN Handling
The eBPF program includes VLAN tag parsing to correctly handle traffic in VLAN-segmented networks. It can parse up to two levels of VLAN tags (802.1Q and 802.1ad QinQ), ensuring accurate traffic accounting in complex network configurations commonly found in enterprise Kubernetes deployments.

### TCX Attachment Benefits
When running on kernel 6.6+, the TCX attachment mode provides significant advantages:
- Faster attachment/detachment
- Lower CPU overhead
- Better integration with kernel BPF subsystem
- Automatic cleanup on agent crash
- No need for qdisc manipulation

The agent automatically detects and uses the best available attachment method for optimal performance and compatibility.