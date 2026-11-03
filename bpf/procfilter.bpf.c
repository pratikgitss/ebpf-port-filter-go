// SPDX-License-Identifier: GPL-2.0
//
// procfilter: for one named process, allow outgoing TCP connections to a single
// port only. Every other TCP connect() made by that process is rejected.
// Other processes are never affected.
//
// Hook: cgroup/connect4 and cgroup/connect6. These run inside the process's own
// connect() system call, so "the current task" is the process we want to
// inspect and bpf_get_current_comm() returns its name. XDP or TC could not do
// this: they run on packets, which are not yet tied to any local process.

#include <linux/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define COMM_LEN 16 // TASK_COMM_LEN: up to 15 name bytes plus a NUL
#define SOCK_STREAM 1 // TCP sockets
#define ALLOW 1 // connect4/connect6 return 1 to let connect() proceed
#define REJECT 0 // ...and 0 to make it fail with a permission error

// target_comm[0] = process name to restrict, NUL padded to 16 bytes (written by Go).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, char[COMM_LEN]);
} target_comm SEC(".maps");

// allowed_port[0] = the only TCP port that process may connect to (host order).
struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} allowed_port SEC(".maps");

// rejected[0] = number of connect() calls rejected (per-CPU, summed by Go).
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} rejected SEC(".maps");

// comm_equal compares two NUL-terminated names stored in 16-byte buffers. The
// loop has a constant bound so the verifier can prove it terminates.
static __always_inline int comm_equal(const char *a, const char *b)
{
#pragma unroll
	for (int i = 0; i < COMM_LEN; i++) {
		if (a[i] != b[i])
			return 0;
		if (a[i] == '\0')
			return 1;
	}
	return 1;
}

static __always_inline int check_connect(struct bpf_sock_addr *ctx)
{
	char comm[COMM_LEN] = {};
	__u32 key = 0;

	// Only TCP is in scope; UDP and other socket types are left alone.
	if (ctx->type != SOCK_STREAM)
		return ALLOW;

	const char *target = bpf_map_lookup_elem(&target_comm, &key);
	__u32 *port = bpf_map_lookup_elem(&allowed_port, &key);
	if (!target || !port)
		return ALLOW; // not configured yet: do not break the system

	if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
		return ALLOW;

	// Not the process we restrict.
	if (!comm_equal(comm, target))
		return ALLOW;

	// user_port is the destination port in network byte order.
	if (bpf_ntohs((__u16)ctx->user_port) == *port)
		return ALLOW;

	__u64 *count = bpf_map_lookup_elem(&rejected, &key);
	if (count)
		*count += 1;

	return REJECT;
}

SEC("cgroup/connect4")
int check_connect4(struct bpf_sock_addr *ctx)
{
	return check_connect(ctx);
}

SEC("cgroup/connect6")
int check_connect6(struct bpf_sock_addr *ctx)
{
	return check_connect(ctx);
}

char LICENSE[] SEC("license") = "GPL";
