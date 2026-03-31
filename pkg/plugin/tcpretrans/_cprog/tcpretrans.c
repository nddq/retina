// go:build ignore

// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// TCP retransmission tracer — tracepoint on tcp/tcp_retransmit_skb.
// Captures the 5-tuple, TCP state, and flags from retransmitted packets.
//
// Ref: https://github.com/inspektor-gadget/inspektor-gadget/blob/c414fc1/gadgets/trace_tcpretrans/program.bpf.c

#include "vmlinux.h"
#include "bpf_helpers.h"
#include "bpf_core_read.h"

char __license[] SEC("license") = "Dual MIT/GPL";

// Kernel < 6.13 uses a shared struct for tcp_retransmit_skb and
// tcp_send_reset tracepoints.  Kernel >= 6.13 splits them into
// per-tracepoint structs and adds an 'err' field.
//
// We define both variants with ___flavor suffixes so that:
//  1. There is no redefinition conflict with whichever vmlinux.h is used
//     (static repo header or runtime-generated per PR #1984).
//  2. CO-RE strips the ___<flavor> suffix during relocation and matches
//     the correct kernel type automatically.
struct trace_event_raw_tcp_event_sk_skb___old {
	struct trace_entry ent;
	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	char __data[0];
};

struct trace_event_raw_tcp_retransmit_skb___new {
	struct trace_entry ent;
	const void *skbaddr;
	const void *skaddr;
	int state;
	__u16 sport;
	__u16 dport;
	__u16 family;
	__u8 saddr[4];
	__u8 daddr[4];
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
	int err;
	char __data[0];
};

// Sent to userspace via perf buffer.
// Fields ordered by descending alignment to minimize padding.
struct tcpretrans_event {
	__u64 timestamp;  // Boot time in nanoseconds
	__u32 src_ip;	  // Source IPv4 (network byte order)
	__u32 dst_ip;	  // Destination IPv4 (network byte order)
	__u32 state;	  // TCP state (e.g., ESTABLISHED, SYN_SENT)
	__u16 src_port;	  // Source port (host byte order)
	__u16 dst_port;	  // Destination port (host byte order)
	__u8 src_ip6[16]; // Source IPv6 address
	__u8 dst_ip6[16]; // Destination IPv6 address
	__u8 tcpflags;	  // TCP flags byte (SYN/ACK/FIN/RST/etc.)
	__u8 af;	  // Address family (4=IPv4, 6=IPv6)
};

// Required by bpf2go -type flag (perf payload, not a map key/value).
const struct tcpretrans_event *unused_tcpretrans_event __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} retina_tcpretrans_events SEC(".maps");

// Read the tracepoint fields common to both struct flavors.
// The verifier eliminates whichever branch is dead on the running kernel.
#define READ_TP_FIELDS(tp_type, ctx, st, sp, dp, sk_out, skb_out)	\
do {									\
	tp_type *__tp = (tp_type *)(ctx);				\
	(st)      = BPF_CORE_READ(__tp, state);				\
	(sp)      = BPF_CORE_READ(__tp, sport);				\
	(dp)      = BPF_CORE_READ(__tp, dport);				\
	(sk_out)  = (const struct sock *)BPF_CORE_READ(__tp, skaddr);	\
	(skb_out) = (const void *)BPF_CORE_READ(__tp, skbaddr);	\
} while (0)

// Tracepoint context fields are accessed via BPF_CORE_READ so that CO-RE
// relocates them against the running kernel's BTF. Direct ctx->field access
// would compile and work on the build-host kernel, but wouldn't survive
// layout changes across kernels.
SEC("tracepoint/tcp/tcp_retransmit_skb")
int retina_tcp_retransmit_skb(void *ctx) {
	struct tcpretrans_event event = {};

	event.timestamp = bpf_ktime_get_boot_ns();

	const struct sock *sk;
	const void *skbaddr;

	// Pick the struct flavor that exists in the running kernel's BTF.
	// bpf_core_type_exists() is resolved at load time; the verifier
	// eliminates the dead branch and its unresolvable CO-RE relocations.
	if (bpf_core_type_exists(struct trace_event_raw_tcp_retransmit_skb___new)) {
		READ_TP_FIELDS(struct trace_event_raw_tcp_retransmit_skb___new,
			       ctx, event.state, event.src_port,
			       event.dst_port, sk, skbaddr);
	} else {
		READ_TP_FIELDS(struct trace_event_raw_tcp_event_sk_skb___old,
			       ctx, event.state, event.src_port,
			       event.dst_port, sk, skbaddr);
	}

	// Address family and IPs are read from the sock — these fields are
	// stable across kernel versions and avoid further type branching.
	__u16 family = 0;
	BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);

	if (family == 2) { // AF_INET
		event.af = 4;
		BPF_CORE_READ_INTO(&event.src_ip, sk,
				    __sk_common.skc_rcv_saddr);
		BPF_CORE_READ_INTO(&event.dst_ip, sk, __sk_common.skc_daddr);
	} else if (family == 10) { // AF_INET6
		event.af = 6;
		BPF_CORE_READ_INTO(event.src_ip6, sk,
				    __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
		BPF_CORE_READ_INTO(event.dst_ip6, sk,
				    __sk_common.skc_v6_daddr.in6_u.u6_addr8);
	} else {
		return 0;
	}

	// TCP flags live in tcp_skb_cb (the control buffer at skb->cb), not in
	// the transport header — the retransmit skb is built from a clone that
	// doesn't carry the TCP header.
	// Note: the offsetof() here is resolved at compile time against the
	// build-host vmlinux.h, not CO-RE relocated. tcp_skb_cb is a stable
	// internal struct, but if it ever changes, this offset would be wrong.
	// Ref: https://github.com/inspektor-gadget/inspektor-gadget/blob/c414fc1/gadgets/trace_tcpretrans/program.bpf.c#L124-L131
	if (skbaddr) {
		bpf_probe_read_kernel(
			&event.tcpflags, sizeof(event.tcpflags),
			skbaddr + offsetof(struct sk_buff, cb) +
				offsetof(struct tcp_skb_cb, tcp_flags));
	}

	bpf_perf_event_output(ctx, &retina_tcpretrans_events, BPF_F_CURRENT_CPU,
			      &event, sizeof(event));

	return 0;
}
