package agent

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 -type ip_key -type ip_value --cc clang netscope netscope.c -- -I. -Wall -O2
