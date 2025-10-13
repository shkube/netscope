//go:build ignore

#include "vmlinux.h"

#define ETH_P_IP 0x0800
#define TC_ACT_OK 0
#define MAX_ENTRIES 10240

// IP key structure for tracking source-destination pairs
struct ip_key {
	__u32 src_ip;
	__u32 dst_ip;
};

// IP value structure for storing traffic bytes
struct ip_value {
	__u64 bytes;
};

// BPF map to store aggregated traffic data
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct ip_key);
	__type(value, struct ip_value);
} ip_traffic_map SEC(".maps");

// Parse Ethernet header, including up to two VLAN tags, returns header length
static __always_inline int parse_ethhdr(struct __sk_buff *skb, __u16 *proto) {
	struct ethhdr eth;
	int offset = 0;

	if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0) {
		return -1;
	}
	offset += sizeof(eth);

	__u16 h_proto = bpf_ntohs(eth.h_proto);

	// Handle up to two VLAN tags (802.1Q and 802.1ad)
	#pragma unroll
	for (int i = 0; i < 2; i++) {
		if (h_proto == 0x8100 /* ETH_P_8021Q */ || h_proto == 0x88a8 /* ETH_P_8021AD */) {
			__u16 encap_proto_be;
			// VLAN header is 4 bytes: TCI (2) + encapsulated proto (2)
			if (bpf_skb_load_bytes(skb, offset + 2, &encap_proto_be, sizeof(encap_proto_be)) < 0) {
				return -1;
			}
			offset += 4; // sizeof(struct { __u16 tci; __u16 proto; })
			h_proto = bpf_ntohs(encap_proto_be);
		} else {
			break;
		}
	}

	*proto = h_proto;
	return offset;
}

// Parse IP header and extract src/dst IPs
static __always_inline int parse_iphdr(struct __sk_buff *skb, int offset,
                                       __u32 *src_ip, __u32 *dst_ip, __u16 *total_len) {
	struct iphdr ip;

	if (bpf_skb_load_bytes(skb, offset, &ip, sizeof(ip)) < 0) {
		return -1;
	}

	// Only handle IPv4
	if (ip.version != 4) {
		return -1;
	}

	*src_ip = ip.saddr;
	*dst_ip = ip.daddr;
	*total_len = bpf_ntohs(ip.tot_len);

	return 0;
}

SEC("tc/egress")
int tc_egress(struct __sk_buff *skb) {
	__u16 eth_proto;
	__u32 src_ip, dst_ip;
	__u16 ip_total_len;

	// Parse Ethernet header
	int eth_len = parse_ethhdr(skb, &eth_proto);
	if (eth_len < 0) {
		return TC_ACT_OK;
	}

	// Only process IPv4 packets
	if (eth_proto != ETH_P_IP) {
		return TC_ACT_OK;
	}

	// Parse IP header
	if (parse_iphdr(skb, eth_len, &src_ip, &dst_ip, &ip_total_len) < 0) {
		return TC_ACT_OK;
	}

	// Create key for the map
	struct ip_key key = {
		.src_ip = src_ip,
		.dst_ip = dst_ip,
	};

	// Look up or create entry in map
	struct ip_value *value = bpf_map_lookup_elem(&ip_traffic_map, &key);
	if (value) {
		// Entry exists, increment bytes
		__sync_fetch_and_add(&value->bytes, ip_total_len);
	} else {
		// Create new entry
		struct ip_value new_value = {
			.bytes = ip_total_len,
		};
		bpf_map_update_elem(&ip_traffic_map, &key, &new_value, BPF_ANY);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
