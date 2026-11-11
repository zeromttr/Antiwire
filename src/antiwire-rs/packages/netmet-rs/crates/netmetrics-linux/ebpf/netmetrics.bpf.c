// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
//
// CO-RE source for the userspace loader in this crate. Generate vmlinux.h for
// the build runner; the resulting object remains portable through BTF CO-RE.

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define NETMETRICS_MAGIC 0x31544d4e
// Version 2 appends the socket cookie. Loaders accept both, so an object built
// before this change still decodes.
#define NETMETRICS_VERSION 3
#define FLOW_OPEN 1
#define FLOW_CLOSE 2
#define FLOW_SENT 3
#define FLOW_RECEIVED 4
#define FLOW_OWNER 5
#define PROTO_TCP 6
#define PROTO_UDP 17
#define FAMILY_V4 4
#define FAMILY_V6 6
#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10
#define TCP_ESTABLISHED_VALUE 1
#define TCP_CLOSE_VALUE 7
// How long a socket's unchanged owner goes unrepeated. Well inside the
// userspace history retention, so a live owner never ages out.
#define OWNER_REFRESH_NS (10ULL * 1000 * 1000 * 1000)

struct wire_flow_record {
    __u32 magic;
    __u8 version;
    __u8 kind;
    __u8 protocol;
    __u8 family;
    __u32 pid;
    __u64 timestamp;
    __u64 byte_count;
    __be16 local_port;
    __be16 remote_port;
    __u8 local_addr[16];
    __u8 remote_addr[16];
    // Socket cookie, or zero when the running kernel lacks the helper.
    __u64 cookie;
    // skc_bound_dev_if, or zero when the socket is unbound.
    __u32 ifindex;
} __attribute__((packed));

struct recv_args {
    struct sock *sk;
    struct msghdr *msg;
};

struct send_args {
    struct sock *sk;
    __u8 remote_family;
    __be16 remote_port;
    __u8 remote_addr[16];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 16 * 1024 * 1024);
} EVENTS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct recv_args);
} UDP_RECV_ARGS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct send_args);
} TCP_SEND_ARGS SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct send_args);
} UDP_SEND_ARGS SEC(".maps");

// Last owner record per socket cookie, to throttle repeats.
struct owner_seen {
    __u32 pid;
    __be16 local_port;
    __u8 local_addr[16];
    __u64 emitted_at;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, struct owner_seen);
} SEND_OWNERS SEC(".maps");

enum send_diagnostic {
    SEND_ENTRY_STORE_FAILED = 0,
    SEND_RETURN_CONTEXT_MISSING = 1,
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 2);
    __type(key, __u32);
    __type(value, __u64);
} SEND_DIAGNOSTICS SEC(".maps");

static __always_inline void count_send_diagnostic(enum send_diagnostic diagnostic)
{
    __u32 key = diagnostic;
    __u64 *value = bpf_map_lookup_elem(&SEND_DIAGNOSTICS, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

static __always_inline int read_ptr(void *dst, __u32 len, const void *src)
{
    if (!src)
        return -1;
    if (bpf_probe_read_kernel(dst, len, src) == 0)
        return 0;
    return bpf_probe_read_user(dst, len, src);
}

static __always_inline int remote_unspecified(const struct wire_flow_record *record)
{
    if (record->remote_port != 0)
        return 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (record->remote_addr[i] != 0)
            return 0;
    }
    return 1;
}

static __always_inline void overlay_msg_name(struct wire_flow_record *record, struct msghdr *msg)
{
    if (!msg || !remote_unspecified(record))
        return;
    void *name = NULL;
    BPF_CORE_READ_INTO(&name, msg, msg_name);
    int namelen = BPF_CORE_READ(msg, msg_namelen);
    if (!name || namelen < 8)
        return;
    unsigned char buf[28] = {};
    __u32 copy = namelen > 28 ? 28 : namelen;
    if (read_ptr(buf, copy, name) != 0)
        return;
    __u16 family = 0;
    __builtin_memcpy(&family, buf, sizeof(family));
    if (family == AF_INET_VALUE && copy >= 16) {
        record->family = FAMILY_V4;
        __builtin_memcpy(record->remote_addr, buf + 4, 4);
        __builtin_memset(record->remote_addr + 4, 0, 12);
        __builtin_memcpy(&record->remote_port, buf + 2, 2);
    } else if (family == AF_INET6_VALUE && copy >= 28) {
        record->family = FAMILY_V6;
        __builtin_memcpy(record->remote_addr, buf + 8, 16);
        __builtin_memcpy(&record->remote_port, buf + 2, 2);
    }
}

static __always_inline void capture_msg_name(struct send_args *args, struct msghdr *msg)
{
    if (!msg)
        return;
    void *name = NULL;
    BPF_CORE_READ_INTO(&name, msg, msg_name);
    int namelen = BPF_CORE_READ(msg, msg_namelen);
    if (!name || namelen < 8)
        return;
    unsigned char buf[28] = {};
    __u32 copy = namelen > 28 ? 28 : namelen;
    if (read_ptr(buf, copy, name) != 0)
        return;
    __u16 family = 0;
    __builtin_memcpy(&family, buf, sizeof(family));
    if (family == AF_INET_VALUE && copy >= 16) {
        args->remote_family = FAMILY_V4;
        __builtin_memcpy(args->remote_addr, buf + 4, 4);
        __builtin_memcpy(&args->remote_port, buf + 2, 2);
    } else if (family == AF_INET6_VALUE && copy >= 28) {
        args->remote_family = FAMILY_V6;
        __builtin_memcpy(args->remote_addr, buf + 8, 16);
        __builtin_memcpy(&args->remote_port, buf + 2, 2);
    }
}

static __always_inline int fill_from_sock(
    struct wire_flow_record *record,
    struct sock *sk,
    __u8 protocol
) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    record->protocol = protocol;
    record->pid = bpf_get_current_pid_tgid() >> 32;
    record->timestamp = bpf_ktime_get_ns();
    // Never reused for the lifetime of the boot, so a changed cookie on an unchanged
    // tuple is proof of a new socket. Zero means the helper is unavailable.
    record->cookie = bpf_get_socket_cookie(sk);
    record->ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
    record->local_port = bpf_htons(BPF_CORE_READ(sk, __sk_common.skc_num));
    record->remote_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    if (family == AF_INET_VALUE) {
        __be32 local = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        __be32 remote = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        record->family = FAMILY_V4;
        __builtin_memcpy(record->local_addr, &local, sizeof(local));
        __builtin_memcpy(record->remote_addr, &remote, sizeof(remote));
        return 0;
    }
    if (family == AF_INET6_VALUE) {
        struct in6_addr local;
        struct in6_addr remote;
        record->family = FAMILY_V6;
        BPF_CORE_READ_INTO(&local, sk, __sk_common.skc_v6_rcv_saddr);
        BPF_CORE_READ_INTO(&remote, sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(record->local_addr, &local, sizeof(local));
        __builtin_memcpy(record->remote_addr, &remote, sizeof(remote));
        return 0;
    }
    return -1;
}

static __always_inline int emit_socket(
    struct sock *sk,
    struct msghdr *msg,
    __u8 protocol,
    __u8 kind,
    __u64 byte_count
) {
    struct wire_flow_record *record = bpf_ringbuf_reserve(&EVENTS, sizeof(*record), 0);
    if (!record)
        return 0;
    __builtin_memset(record, 0, sizeof(*record));
    record->magic = NETMETRICS_MAGIC;
    record->version = NETMETRICS_VERSION;
    record->kind = kind;
    record->byte_count = byte_count;
    if (fill_from_sock(record, sk, protocol) != 0) {
        bpf_ringbuf_discard(record, 0);
        return 0;
    }
    if (protocol == PROTO_UDP)
        overlay_msg_name(record, msg);
    bpf_ringbuf_submit(record, 0);
    return 0;
}

static __always_inline int emit_send(
    const struct send_args *args,
    __u8 protocol,
    __u64 byte_count
) {
    struct wire_flow_record *record = bpf_ringbuf_reserve(&EVENTS, sizeof(*record), 0);
    if (!record)
        return 0;
    __builtin_memset(record, 0, sizeof(*record));
    record->magic = NETMETRICS_MAGIC;
    record->version = NETMETRICS_VERSION;
    record->kind = FLOW_SENT;
    record->byte_count = byte_count;
    if (fill_from_sock(record, args->sk, protocol) != 0) {
        bpf_ringbuf_discard(record, 0);
        return 0;
    }
    if (protocol == PROTO_UDP && remote_unspecified(record) && args->remote_family != 0) {
        record->family = args->remote_family;
        record->remote_port = args->remote_port;
        __builtin_memcpy(record->remote_addr, args->remote_addr, sizeof(record->remote_addr));
    }
    bpf_ringbuf_submit(record, 0);
    return 0;
}

static __always_inline int same_local_endpoint(
    const struct owner_seen *seen,
    const struct wire_flow_record *record
) {
    if (seen->pid != record->pid || seen->local_port != record->local_port)
        return 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (seen->local_addr[i] != record->local_addr[i])
            return 0;
    }
    return 1;
}

// Names the sending process at sendmsg entry. The receiver can read the
// packet before sendmsg returns, so the byte record comes too late to prove
// who owned the endpoint when it arrived. The time is read before the record
// takes its ring position, so a record timed after a query's arrival is
// always consumed after every owner record emitted before it.
static __always_inline void emit_owner(struct sock *sk, __u8 protocol)
{
    __u64 started_at = bpf_ktime_get_ns();
    struct wire_flow_record record = {};
    record.magic = NETMETRICS_MAGIC;
    record.version = NETMETRICS_VERSION;
    record.kind = FLOW_OWNER;
    if (fill_from_sock(&record, sk, protocol) != 0)
        return;
    record.timestamp = started_at;
    __u64 cookie = record.cookie;
    if (cookie != 0) {
        struct owner_seen *seen = bpf_map_lookup_elem(&SEND_OWNERS, &cookie);
        if (seen && same_local_endpoint(seen, &record) &&
            started_at - seen->emitted_at < OWNER_REFRESH_NS)
            return;
    }
    if (bpf_ringbuf_output(&EVENTS, &record, sizeof(record), 0) != 0 || cookie == 0)
        return;
    struct owner_seen next = {
        .pid = record.pid,
        .local_port = record.local_port,
        .emitted_at = started_at,
    };
    __builtin_memcpy(next.local_addr, record.local_addr, sizeof(next.local_addr));
    bpf_map_update_elem(&SEND_OWNERS, &cookie, &next, BPF_ANY);
}

SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != PROTO_TCP)
        return 0;
    __u8 kind;
    if (ctx->newstate == TCP_ESTABLISHED_VALUE &&
        ctx->oldstate != TCP_ESTABLISHED_VALUE)
        kind = FLOW_OPEN;
    else if (ctx->newstate == TCP_CLOSE_VALUE)
        kind = FLOW_CLOSE;
    else
        return 0;

    struct wire_flow_record *record = bpf_ringbuf_reserve(&EVENTS, sizeof(*record), 0);
    if (!record)
        return 0;
    __builtin_memset(record, 0, sizeof(*record));
    record->magic = NETMETRICS_MAGIC;
    record->version = NETMETRICS_VERSION;
    record->kind = kind;
    record->protocol = PROTO_TCP;
    // pid stays 0 (unknown). TCP changes state wherever the kernel processes the
    // socket, often in softirq on the receive path, so the current task is not
    // evidence of the owner. Byte probes run in the owner's syscalls and procfs
    // reconciliation reads descriptors; both fill in the owner of a PID-0 flow.
    record->timestamp = bpf_ktime_get_ns();
    record->local_port = bpf_htons(ctx->sport);
    record->remote_port = bpf_htons(ctx->dport);
    {
        // Field read rather than bpf_get_socket_cookie: the helper is not available to
        // every tracepoint program type, and this is the same word the helper returns.
        struct sock *sk = (struct sock *)ctx->skaddr;
        record->cookie = (__u64)BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
        record->ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
    }
    if (ctx->family == AF_INET_VALUE) {
        record->family = FAMILY_V4;
        __builtin_memcpy(record->local_addr, ctx->saddr, 4);
        __builtin_memcpy(record->remote_addr, ctx->daddr, 4);
    } else if (ctx->family == AF_INET6_VALUE) {
        record->family = FAMILY_V6;
        __builtin_memcpy(record->local_addr, ctx->saddr_v6, 16);
        __builtin_memcpy(record->remote_addr, ctx->daddr_v6, 16);
    } else {
        bpf_ringbuf_discard(record, 0);
        return 0;
    }
    bpf_ringbuf_submit(record, 0);
    return 0;
}

SEC("kprobe/tcp_sendmsg")
int BPF_KPROBE(
    trace_tcp_sendmsg,
    struct sock *sk,
    struct msghdr *msg,
    size_t size
) {
    __u64 id = bpf_get_current_pid_tgid();
    emit_owner(sk, PROTO_TCP);
    struct send_args args = {.sk = sk};
    if (bpf_map_update_elem(&TCP_SEND_ARGS, &id, &args, BPF_ANY) != 0)
        count_send_diagnostic(SEND_ENTRY_STORE_FAILED);
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(complete_tcp_sendmsg, long sent) {
    __u64 id = bpf_get_current_pid_tgid();
    struct send_args *stored = bpf_map_lookup_elem(&TCP_SEND_ARGS, &id);
    if (!stored) {
        count_send_diagnostic(SEND_RETURN_CONTEXT_MISSING);
        return 0;
    }
    struct send_args args = *stored;
    bpf_map_delete_elem(&TCP_SEND_ARGS, &id);
    if (sent <= 0)
        return 0;
    return emit_send(&args, PROTO_TCP, sent);
}

SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    if (copied <= 0)
        return 0;
    return emit_socket(sk, NULL, PROTO_TCP, FLOW_RECEIVED, copied);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(
    trace_udp_sendmsg,
    struct sock *sk,
    struct msghdr *msg,
    size_t length
) {
    __u64 id = bpf_get_current_pid_tgid();
    emit_owner(sk, PROTO_UDP);
    struct send_args args = {.sk = sk};
    capture_msg_name(&args, msg);
    if (bpf_map_update_elem(&UDP_SEND_ARGS, &id, &args, BPF_ANY) != 0)
        count_send_diagnostic(SEND_ENTRY_STORE_FAILED);
    return 0;
}

SEC("kretprobe/udp_sendmsg")
int BPF_KRETPROBE(complete_udp_sendmsg, long sent) {
    __u64 id = bpf_get_current_pid_tgid();
    struct send_args *stored = bpf_map_lookup_elem(&UDP_SEND_ARGS, &id);
    if (!stored) {
        count_send_diagnostic(SEND_RETURN_CONTEXT_MISSING);
        return 0;
    }
    struct send_args args = *stored;
    bpf_map_delete_elem(&UDP_SEND_ARGS, &id);
    if (sent <= 0)
        return 0;
    return emit_send(&args, PROTO_UDP, sent);
}

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(track_udp_recvmsg, struct sock *sk, struct msghdr *msg) {
    __u64 id = bpf_get_current_pid_tgid();
    struct recv_args args = {.sk = sk, .msg = msg};
    bpf_map_update_elem(&UDP_RECV_ARGS, &id, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(trace_udp_recvmsg, int copied) {
    __u64 id = bpf_get_current_pid_tgid();
    struct recv_args *args = bpf_map_lookup_elem(&UDP_RECV_ARGS, &id);
    if (!args)
        return 0;
    struct sock *sk = args->sk;
    struct msghdr *msg = args->msg;
    bpf_map_delete_elem(&UDP_RECV_ARGS, &id);
    if (copied <= 0)
        return 0;
    return emit_socket(sk, msg, PROTO_UDP, FLOW_RECEIVED, copied);
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(trace_udp_destroy_sock, struct sock *sk) {
    return emit_socket(sk, NULL, PROTO_UDP, FLOW_CLOSE, 0);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
