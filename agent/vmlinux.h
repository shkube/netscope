#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#pragma once

typedef unsigned char __u8;
typedef unsigned short __u16;
typedef unsigned int __u32;
typedef unsigned long long __u64;

typedef signed char __s8;
typedef signed short __s16;
typedef signed int __s32;
typedef signed long long __s64;

// Additional types for network programming
typedef __u16 __be16;
typedef __u32 __be32;
typedef __u32 __wsum;

// Minimal definitions needed for TC and networking eBPF programs

struct ethhdr {
	unsigned char h_dest[6];
	unsigned char h_source[6];
	__u16 h_proto;
} __attribute__((packed));

struct iphdr {
	__u8 ihl:4,
	     version:4;
	__u8 tos;
	__u16 tot_len;
	__u16 id;
	__u16 frag_off;
	__u8 ttl;
	__u8 protocol;
	__u16 check;
	__u32 saddr;
	__u32 daddr;
} __attribute__((packed));

// sk_buff structure (minimal)
struct __sk_buff {
	__u32 len;
	__u32 pkt_type;
	__u32 mark;
	__u32 queue_mapping;
	__u32 protocol;
	__u32 vlan_present;
	__u32 vlan_tci;
	__u32 vlan_proto;
	__u32 priority;
	__u32 ingress_ifindex;
	__u32 ifindex;
	__u32 tc_index;
	__u32 cb[5];
	__u32 hash;
	__u32 tc_classid;
	__u32 data;
	__u32 data_end;
	__u32 napi_id;
	__u32 family;
	__u32 remote_ip4;
	__u32 local_ip4;
	__u32 remote_ip6[4];
	__u32 local_ip6[4];
	__u32 remote_port;
	__u32 local_port;
	__u32 data_meta;
	__u32 flow_keys;
	__u64 tstamp;
	__u32 wire_len;
	__u32 gso_segs;
	__u32 sk;
	__u32 gso_size;
	__u32 tstamp_type;
	__u64 hwtstamp;
};

enum bpf_map_type {
	BPF_MAP_TYPE_HASH = 1,
};

enum {
	BPF_ANY = 0,
};

// BPF helper function declarations
static long (*bpf_skb_load_bytes)(const void *skb, __u32 offset, void *to, __u32 len) = (void *) 26;
static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *) 1;
static long (*bpf_map_update_elem)(void *map, const void *key, const void *value, __u64 flags) = (void *) 2;

// Endianness helpers
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define bpf_ntohs(x) __builtin_bswap16(x)
#define bpf_htons(x) __builtin_bswap16(x)
#define bpf_ntohl(x) __builtin_bswap32(x)
#define bpf_htonl(x) __builtin_bswap32(x)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define bpf_ntohs(x) (x)
#define bpf_htons(x) (x)
#define bpf_ntohl(x) (x)
#define bpf_htonl(x) (x)
#endif

// Map flags
#define BPF_ANY 0
#define BPF_MAP_TYPE_HASH 1

// Section and type macros
#define SEC(name) __attribute__((section(name), used))
#define __always_inline inline __attribute__((always_inline))
#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

// Atomic operations
#define __sync_fetch_and_add(ptr, val) __sync_fetch_and_add(ptr, val)

#endif /* __VMLINUX_H__ */
