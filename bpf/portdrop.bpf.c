// SPDX-License-Identifier: GPL-2.0
//
// portdrop: drop incoming TCP packets whose destination port equals the value
// stored in the `config` map. Userspace (Go) writes that value, so the port can
// be changed without recompiling and even while the program is running.
//
// Hook: XDP, the earliest point on the receive path. XDP only sees raw packets;
// it cannot tell which process a packet belongs to (see procfilter.bpf.c for that).

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

// config[0] = TCP destination port to drop (host byte order, written by Go).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} config SEC(".maps");

// dropped[0] = number of packets dropped. Per-CPU, so no locking is needed;
// userspace sums the per-CPU values.
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} dropped SEC(".maps");

// parse_tcp returns a pointer to the TCP header of an Ethernet/IPv4/TCP or
// Ethernet/IPv6/TCP packet, or NULL for anything else. Every pointer is checked
// against data_end before it is used: the verifier rejects the program otherwise.
static __always_inline struct tcphdr *parse_tcp(void *data, void *data_end)
{
	struct ethhdr *eth = data;
	if ((void *)(eth + 1) > data_end)
		return NULL;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return NULL;
		if (ip->protocol != IPPROTO_TCP)
			return NULL;

		// The IPv4 header length is variable: ihl counts 4-byte words.
		__u32 hlen = ip->ihl * 4;
		if (hlen < sizeof(*ip))
			return NULL;

		struct tcphdr *tcp = (void *)ip + hlen;
		if ((void *)(tcp + 1) > data_end)
			return NULL;
		return tcp;
	}

	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		if ((void *)(ip6 + 1) > data_end)
			return NULL;
		// Only handles TCP directly after the fixed IPv6 header (no extension headers).
		if (ip6->nexthdr != IPPROTO_TCP)
			return NULL;

		struct tcphdr *tcp = (void *)(ip6 + 1);
		if ((void *)(tcp + 1) > data_end)
			return NULL;
		return tcp;
	}

	return NULL;
}

SEC("xdp")
int drop_tcp_port(struct xdp_md *ctx)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u32 key = 0;

	// Every map lookup can return NULL; the verifier insists on this check.
	__u32 *port = bpf_map_lookup_elem(&config, &key);
	if (!port)
		return XDP_PASS;

	struct tcphdr *tcp = parse_tcp(data, data_end);
	if (!tcp)
		return XDP_PASS;

	// Header fields are big-endian; convert our port instead of the packet's.
	if (tcp->dest != bpf_htons((__u16)*port))
		return XDP_PASS;

	__u64 *count = bpf_map_lookup_elem(&dropped, &key);
	if (count)
		*count += 1;

	return XDP_DROP;
}

// The GPL license is required: some BPF helpers refuse to load otherwise.
char LICENSE[] SEC("license") = "GPL";
