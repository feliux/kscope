//go:build ignore

#include "vmlinux.h"

#ifndef AF_INET
#define AF_INET 2
#endif

struct sockaddr_in_min {
	__u16 sin_family;
	__u16 sin_port;
	__u32 sin_addr;
};

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_DNS_PAYLOAD 256

enum event_type {
	EVENT_TCP_CONNECT = 1,
	EVENT_DNS_QUERY = 2,
	EVENT_DNS_REPLY = 3,
	EVENT_PROCESS_EXEC = 4,
};

enum redirect_stat_index {
	REDIR_STAT_CONNECT4_SEEN = 0,
	REDIR_STAT_CONNECT4_MATCHED = 1,
	REDIR_STAT_CONNECT4_REDIRECTED = 2,
	REDIR_STAT_CONNECT6_SEEN = 3,
	REDIR_STAT_CONNECT6_MATCHED = 4,
	REDIR_STAT_CONNECT6_REDIRECTED = 5,
};

struct tcp_event_t {
	__u8 ip_version;
	__u8 success;
	__u16 sport;
	__u16 dport;
	__u16 pad;
	__u32 saddr_v4;
	__u32 daddr_v4;
	__u8 saddr_v6[16];
	__u8 daddr_v6[16];
};

struct rule_value_t {
	__u8 enabled;
};

struct redirect_stat_t {
	__u64 count;
};

struct domain_value_t {
	__u64 expires_at_ns;
};

struct ip_port_v4_t {
	__u32 ip;
	__u16 port;
	__u16 pad;
};

struct ip_port_v6_t {
	__u8 ip[16];
	__u16 port;
	__u16 pad;
};

struct proxy_target_v4_t {
	__u32 ip;
	__u16 port;
	__u16 pad;
};

struct proxy_target_v6_t {
	__u8 ip[16];
	__u16 port;
	__u16 pad;
};



struct orig_dst_t {
	__u8 ip_version;
	__u8 pad;
	__u16 port;
	__u32 addr_v4;
	__u8 addr_v6[16];
};

struct flow_key_v4_t {
	__u32 src_ip;
	__u16 src_port;
	__u16 pad;
};

struct flow_key_v6_t {
	__u8 src_ip[16];
	__u16 src_port;
	__u16 pad;
};

struct pid_port_key_t {
	__u32 pid;
	__u16 port;
	__u8 ip_version;
	__u8 pad;
};

struct dns_event_t {
	__u32 payload_len;
	__u8 payload[MAX_DNS_PAYLOAD];
};

struct process_event_t {
	__u32 ppid;
};

struct event_t {
	__u32 type;
	__u32 pid;
	__u64 ts_ns;
	char comm[16];

	union {
		struct tcp_event_t tcp;
		struct dns_event_t dns;
		struct process_event_t proc;
	};
};

struct recv_args_t {
	__u64 buf;
	__u64 len;
	__u64 addr;
	__u64 addrlen_ptr;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct sock *);
} socks SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct recv_args_t);
} recv_args SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rule_value_t);
} rules_pid SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct rule_value_t);
} rules_pid_exempt SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, char[16]);
	__type(value, struct rule_value_t);
} rules_comm SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_port_v4_t);
	__type(value, struct rule_value_t);
} rules_ipport_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_port_v6_t);
	__type(value, struct rule_value_t);
} rules_ipport_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_port_v4_t);
	__type(value, struct domain_value_t);
} rules_domain_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct ip_port_v6_t);
	__type(value, struct domain_value_t);
} rules_domain_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proxy_target_v4_t);
} proxy_target_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct proxy_target_v6_t);
} proxy_target_v6 SEC(".maps");



struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, __u64);
	__type(value, struct orig_dst_t);
} orig_dst SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, struct flow_key_v4_t);
	__type(value, struct orig_dst_t);
} orig_dst_flow_v4 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, struct flow_key_v6_t);
	__type(value, struct orig_dst_t);
} orig_dst_flow_v6 SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65535);
	__type(key, struct pid_port_key_t);
	__type(value, struct orig_dst_t);
} orig_dst_pid_port SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, __u32);
	__type(value, struct orig_dst_t);
} redirect_ctx SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 6);
	__type(key, __u32);
	__type(value, struct redirect_stat_t);
} redirect_stats SEC(".maps");

static __always_inline void fill_common(struct event_t *event, __u32 type)
{
	event->type = type;
	event->pid = bpf_get_current_pid_tgid() >> 32;
	event->ts_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
}

static __always_inline void inc_stat(__u32 idx)
{
	struct redirect_stat_t *val = bpf_map_lookup_elem(&redirect_stats, &idx);
	if (val)
		__sync_fetch_and_add(&val->count, 1);
}

static __always_inline int has_rule_pid(__u32 pid)
{
	return bpf_map_lookup_elem(&rules_pid, &pid) != NULL;
}

static __always_inline int is_exempt_pid(__u32 pid)
{
	return bpf_map_lookup_elem(&rules_pid_exempt, &pid) != NULL;
}

static __always_inline int has_rule_comm(void)
{
	char comm[16];
	bpf_get_current_comm(&comm, sizeof(comm));
	return bpf_map_lookup_elem(&rules_comm, &comm) != NULL;
}

static __always_inline int has_rule_ipport_v4(__u32 ip, __u16 port)
{
	struct ip_port_v4_t key = {
		.ip = ip,
		.port = port,
	};

	if (bpf_map_lookup_elem(&rules_ipport_v4, &key))
		return 1;

	key.port = 0;
	if (bpf_map_lookup_elem(&rules_ipport_v4, &key))
		return 1;

	key.ip = bpf_ntohl(ip);
	key.port = port;
	if (bpf_map_lookup_elem(&rules_ipport_v4, &key))
		return 1;

	key.port = 0;
	return bpf_map_lookup_elem(&rules_ipport_v4, &key) != NULL;
}

static __always_inline int has_rule_ipport_v6(__u8 ip[16], __u16 port)
{
	struct ip_port_v6_t key = {};
	__builtin_memcpy(key.ip, ip, sizeof(key.ip));
	key.port = port;

	if (bpf_map_lookup_elem(&rules_ipport_v6, &key))
		return 1;

	key.port = 0;
	return bpf_map_lookup_elem(&rules_ipport_v6, &key) != NULL;
}

static __always_inline int has_domain_rule_v4(__u32 ip, __u16 port)
{
	struct ip_port_v4_t key = {
		.ip = ip,
		.port = port,
	};
	__u64 now = bpf_ktime_get_ns();

	struct domain_value_t *val = bpf_map_lookup_elem(&rules_domain_v4, &key);
	if (val) {
		if (val->expires_at_ns > now)
			return 1;
		bpf_map_delete_elem(&rules_domain_v4, &key);
	}

	key.port = 0;
	val = bpf_map_lookup_elem(&rules_domain_v4, &key);
	if (val) {
		if (val->expires_at_ns > now)
			return 1;
		bpf_map_delete_elem(&rules_domain_v4, &key);
	}

	return 0;
}

static __always_inline int has_domain_rule_v6(__u8 ip[16], __u16 port)
{
	struct ip_port_v6_t key = {};
	__builtin_memcpy(key.ip, ip, sizeof(key.ip));
	key.port = port;
	__u64 now = bpf_ktime_get_ns();

	struct domain_value_t *val = bpf_map_lookup_elem(&rules_domain_v6, &key);
	if (val) {
		if (val->expires_at_ns > now)
			return 1;
		bpf_map_delete_elem(&rules_domain_v6, &key);
	}

	key.port = 0;
	val = bpf_map_lookup_elem(&rules_domain_v6, &key);
	if (val) {
		if (val->expires_at_ns > now)
			return 1;
		bpf_map_delete_elem(&rules_domain_v6, &key);
	}

	return 0;
}

static __always_inline int should_redirect_v4(__u32 ip, __u16 port)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (is_exempt_pid(pid))
		return 0;

	if (has_rule_pid(pid))
		return 1;

	if (has_rule_comm())
		return 1;

	if (has_rule_ipport_v4(ip, port))
		return 1;

	return has_domain_rule_v4(ip, port);
}

static __always_inline int should_redirect_v6(__u8 ip[16], __u16 port)
{
	__u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (is_exempt_pid(pid))
		return 0;

	if (has_rule_pid(pid))
		return 1;

	if (has_rule_comm())
		return 1;

	if (has_rule_ipport_v6(ip, port))
		return 1;

	return has_domain_rule_v6(ip, port);
}

SEC("kprobe/tcp_v4_connect")
int kprobe_tcp_v4_connect(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&socks, &tid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v4_connect")
int kretprobe_tcp_v4_connect(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct sock **skpp = bpf_map_lookup_elem(&socks, &tid);
	if (!skpp)
		return 0;

	struct sock *sk = *skpp;

	struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&socks, &tid);
		return 0;
	}

	fill_common(event, EVENT_TCP_CONNECT);
	__builtin_memset(&event->tcp, 0, sizeof(event->tcp));
	event->tcp.ip_version = 4;
	BPF_CORE_READ_INTO(&event->tcp.saddr_v4, sk, __sk_common.skc_rcv_saddr);
	BPF_CORE_READ_INTO(&event->tcp.daddr_v4, sk, __sk_common.skc_daddr);
	BPF_CORE_READ_INTO(&event->tcp.sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&event->tcp.dport, sk, __sk_common.skc_dport);
	event->tcp.success = PT_REGS_RC(ctx) == 0;

	struct orig_dst_t *redir = bpf_map_lookup_elem(&redirect_ctx, &tid);
	if (redir) {
		if (event->tcp.success) {
			struct flow_key_v4_t fkey = {
				.src_ip = event->tcp.saddr_v4,
				.src_port = event->tcp.sport,
			};
			bpf_map_update_elem(&orig_dst_flow_v4, &fkey, redir, BPF_ANY);

			struct pid_port_key_t pkey = {
				.pid = event->pid,
				.port = event->tcp.sport,
				.ip_version = 4,
			};
			bpf_map_update_elem(&orig_dst_pid_port, &pkey, redir, BPF_ANY);

			pkey.pid = 0;
			bpf_map_update_elem(&orig_dst_pid_port, &pkey, redir, BPF_ANY);
		}
		bpf_map_delete_elem(&redirect_ctx, &tid);
	}

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&socks, &tid);

	return 0;
}

SEC("kprobe/tcp_v6_connect")
int kprobe_tcp_v6_connect(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);

	bpf_map_update_elem(&socks, &tid, &sk, BPF_ANY);
	return 0;
}

SEC("kretprobe/tcp_v6_connect")
int kretprobe_tcp_v6_connect(struct pt_regs *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct sock **skpp = bpf_map_lookup_elem(&socks, &tid);
	if (!skpp)
		return 0;

	struct sock *sk = *skpp;

	struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&socks, &tid);
		return 0;
	}

	fill_common(event, EVENT_TCP_CONNECT);
	__builtin_memset(&event->tcp, 0, sizeof(event->tcp));
	event->tcp.ip_version = 6;
	BPF_CORE_READ_INTO(&event->tcp.sport, sk, __sk_common.skc_num);
	BPF_CORE_READ_INTO(&event->tcp.dport, sk, __sk_common.skc_dport);
	event->tcp.success = PT_REGS_RC(ctx) == 0;

	struct in6_addr saddr = {};
	struct in6_addr daddr = {};
	BPF_CORE_READ_INTO(&saddr, sk, __sk_common.skc_v6_rcv_saddr);
	BPF_CORE_READ_INTO(&daddr, sk, __sk_common.skc_v6_daddr);
	__builtin_memcpy(event->tcp.saddr_v6, &saddr, sizeof(saddr));
	__builtin_memcpy(event->tcp.daddr_v6, &daddr, sizeof(daddr));

	struct orig_dst_t *redir = bpf_map_lookup_elem(&redirect_ctx, &tid);
	if (redir) {
		if (event->tcp.success) {
			struct flow_key_v6_t fkey = {};
			__builtin_memcpy(fkey.src_ip, event->tcp.saddr_v6, sizeof(fkey.src_ip));
			fkey.src_port = event->tcp.sport;
			bpf_map_update_elem(&orig_dst_flow_v6, &fkey, redir, BPF_ANY);

			struct pid_port_key_t pkey = {
				.pid = event->pid,
				.port = event->tcp.sport,
				.ip_version = 6,
			};
			bpf_map_update_elem(&orig_dst_pid_port, &pkey, redir, BPF_ANY);

			pkey.pid = 0;
			bpf_map_update_elem(&orig_dst_pid_port, &pkey, redir, BPF_ANY);
		}
		bpf_map_delete_elem(&redirect_ctx, &tid);
	}

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&socks, &tid);

	return 0;
}

SEC("cgroup/connect4")
int cgroup_connect4(struct bpf_sock_addr *ctx)
{
	__u32 ip = ctx->user_ip4;
	__u16 port = bpf_ntohs(ctx->user_port);

	inc_stat(REDIR_STAT_CONNECT4_SEEN);

	if (!should_redirect_v4(ip, port))
		return 1;

	inc_stat(REDIR_STAT_CONNECT4_MATCHED);

	__u32 key = 0;
	struct proxy_target_v4_t *proxy = bpf_map_lookup_elem(&proxy_target_v4, &key);
	if (!proxy || proxy->port == 0)
		return 1;

	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	struct orig_dst_t orig = {};
	orig.ip_version = 4;
	orig.port = port;
	orig.addr_v4 = ip;

	bpf_map_update_elem(&redirect_ctx, &tid, &orig, BPF_ANY);

	inc_stat(REDIR_STAT_CONNECT4_REDIRECTED);

	ctx->user_ip4 = proxy->ip;
	ctx->user_port = bpf_htons(proxy->port);

	return 1;
}

SEC("cgroup/connect6")
int cgroup_connect6(struct bpf_sock_addr *ctx)
{
	__u32 ip6_0 = ctx->user_ip6[0];
	__u32 ip6_1 = ctx->user_ip6[1];
	__u32 ip6_2 = ctx->user_ip6[2];
	__u32 ip6_3 = ctx->user_ip6[3];
	__u8 ip[16] = {};
	__builtin_memcpy(ip, &ip6_0, 4);
	__builtin_memcpy(ip + 4, &ip6_1, 4);
	__builtin_memcpy(ip + 8, &ip6_2, 4);
	__builtin_memcpy(ip + 12, &ip6_3, 4);
	__u16 port = bpf_ntohs(ctx->user_port);

	inc_stat(REDIR_STAT_CONNECT6_SEEN);

	if (!should_redirect_v6(ip, port))
		return 1;

	inc_stat(REDIR_STAT_CONNECT6_MATCHED);

	__u32 key = 0;
	struct proxy_target_v6_t *proxy = bpf_map_lookup_elem(&proxy_target_v6, &key);
	if (!proxy || proxy->port == 0)
		return 1;

	struct orig_dst_t orig = {};
	orig.ip_version = 6;
	orig.port = port;
	__builtin_memcpy(orig.addr_v6, ip, sizeof(orig.addr_v6));

	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&redirect_ctx, &tid, &orig, BPF_ANY);

	__u32 p0 = 0, p1 = 0, p2 = 0, p3 = 0;
	__builtin_memcpy(&p0, proxy->ip, 4);
	__builtin_memcpy(&p1, proxy->ip + 4, 4);
	__builtin_memcpy(&p2, proxy->ip + 8, 4);
	__builtin_memcpy(&p3, proxy->ip + 12, 4);
	inc_stat(REDIR_STAT_CONNECT6_REDIRECTED);

	ctx->user_ip6[0] = p0;
	ctx->user_ip6[1] = p1;
	ctx->user_ip6[2] = p2;
	ctx->user_ip6[3] = p3;
	ctx->user_port = bpf_htons(proxy->port);

	return 1;
}

SEC("tracepoint/syscalls/sys_enter_sendto")
int tracepoint_sys_enter_sendto(struct trace_event_raw_sys_enter *ctx)
{
	const void *buf = (const void *)ctx->args[1];
	__u64 len = (__u64)ctx->args[2];
	const struct sockaddr *addr = (const struct sockaddr *)ctx->args[4];
	int addrlen = (int)ctx->args[5];

	if (!buf || !addr)
		return 0;

	if (addrlen < sizeof(struct sockaddr_in_min))
		return 0;

	struct sockaddr_in_min sin = {};
	if (bpf_probe_read_user(&sin, sizeof(sin), addr) < 0)
		return 0;

	if (sin.sin_family != AF_INET)
		return 0;

	if (sin.sin_port != bpf_htons(53))
		return 0;

	if (len < 12)
		return 0;

	int read_len = len < MAX_DNS_PAYLOAD ? (int)len : MAX_DNS_PAYLOAD;

	struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	__builtin_memset(&event->dns, 0, sizeof(event->dns));
	fill_common(event, EVENT_DNS_QUERY);
	event->dns.payload_len = read_len;

	if (bpf_probe_read_user(event->dns.payload, read_len, buf) < 0) {
		bpf_ringbuf_discard(event, 0);
		return 0;
	}

	bpf_ringbuf_submit(event, 0);
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_recvfrom")
int tracepoint_sys_enter_recvfrom(struct trace_event_raw_sys_enter *ctx)
{
	struct recv_args_t args = {};
	__u32 tid = (__u32)bpf_get_current_pid_tgid();

	args.buf = ctx->args[1];
	args.len = ctx->args[2];
	args.addr = ctx->args[4];
	args.addrlen_ptr = ctx->args[5];

	bpf_map_update_elem(&recv_args, &tid, &args, BPF_ANY);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_recvfrom")
int tracepoint_sys_exit_recvfrom(struct trace_event_raw_sys_exit *ctx)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct recv_args_t *args = bpf_map_lookup_elem(&recv_args, &tid);
	if (!args)
		return 0;

	long ret = ctx->ret;
	if (ret <= 0) {
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	if (!args->addr || !args->buf) {
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	int addrlen = 0;
	if (args->addrlen_ptr) {
		if (bpf_probe_read_user(&addrlen, sizeof(addrlen), (void *)args->addrlen_ptr) < 0) {
			bpf_map_delete_elem(&recv_args, &tid);
			return 0;
		}
	}

	if (addrlen < sizeof(struct sockaddr_in_min)) {
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	struct sockaddr_in_min sin = {};
	if (bpf_probe_read_user(&sin, sizeof(sin), (void *)args->addr) < 0) {
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	if (sin.sin_family != AF_INET || sin.sin_port != bpf_htons(53)) {
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	int read_len = ret < MAX_DNS_PAYLOAD ? (int)ret : MAX_DNS_PAYLOAD;

	struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event) {
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	__builtin_memset(&event->dns, 0, sizeof(event->dns));
	fill_common(event, EVENT_DNS_REPLY);
	event->dns.payload_len = read_len;

	if (bpf_probe_read_user(event->dns.payload, read_len, (void *)args->buf) < 0) {
		bpf_ringbuf_discard(event, 0);
		bpf_map_delete_elem(&recv_args, &tid);
		return 0;
	}

	bpf_ringbuf_submit(event, 0);
	bpf_map_delete_elem(&recv_args, &tid);
	return 0;
}

SEC("tracepoint/sched/sched_process_exec")
int tracepoint_sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	struct event_t *event = bpf_ringbuf_reserve(&events, sizeof(*event), 0);
	if (!event)
		return 0;

	fill_common(event, EVENT_PROCESS_EXEC);

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	event->proc.ppid = BPF_CORE_READ(task, real_parent, tgid);

	bpf_ringbuf_submit(event, 0);
	return 0;
}