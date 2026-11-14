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
#define PROCESS_EXEC 6
#define PROCESS_EXIT 7
#define FLOW_FINISHING 8
#define PROTO_TCP 6
#define PROTO_UDP 17
#define FAMILY_V4 4
#define FAMILY_V6 6
#define AF_INET_VALUE 2
#define AF_INET6_VALUE 10
#define TCP_ESTABLISHED_VALUE 1
#define TCP_CLOSE_VALUE 7
#define TCP_CLOSE_WAIT_VALUE 8
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
    // Socket cookie, or zero when the kernel has not assigned one (see socket_cookie).
    __u64 cookie;
    // skc_bound_dev_if, or zero when the socket is unbound.
    __u32 ifindex;
} __attribute__((packed));

// A process changing its program or ending, in the same ring as the flow records and
// with the same first six bytes. Decoded by netmetrics_sys::WireProcessRecord.
struct wire_process_record {
    __u32 magic;
    __u8 version;
    __u8 kind;
    __u8 reserved[2];
    __u32 pid;
    __u64 timestamp;
    // When the process started, in nanoseconds since boot: the value /proc/<pid>/stat
    // reports as starttime, before its conversion to clock ticks.
    __u64 start_boottime;
    // The thread group leader's comm, as /proc/<pid>/comm shows it.
    char comm[16];
} __attribute__((packed));

// The loader's PID namespace, as stat(2) reports /proc/self/ns/pid: its device and inode.
// The loader sets both only when it does not run in the initial PID namespace, as inside a
// container or WSL. There the kernel's own PID for a task is not the number the loader's
// /proc lists it under, so records carry the PID as that namespace numbers it.
volatile const __u64 LOADER_PIDNS_DEV = 0;
volatile const __u64 LOADER_PIDNS_INO = 0;

// The running process's PID as the loader sees it in /proc, or zero for a process outside
// the loader's PID namespace, which /proc there does not list at all.
static __always_inline __u32 current_pid(void)
{
    if (LOADER_PIDNS_INO) {
        struct bpf_pidns_info ns = {};
        if (bpf_get_ns_current_pid_tgid(LOADER_PIDNS_DEV, LOADER_PIDNS_INO, &ns, sizeof(ns)))
            return 0;
        return ns.tgid;
    }
    return bpf_get_current_pid_tgid() >> 32;
}

struct recv_args {
    struct sock *sk;
    struct msghdr *msg;
    // Set by trace_skb_consume_udp when the read left its datagram queued.
    __u64 peeked;
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

// Last owner record per socket: it throttles repeats, and names the owner where the
// running task cannot (see recorded_owner). Keyed by the socket's kernel address, not its
// cookie, because a socket can have no cookie (see socket_cookie). A freed socket's address
// can be reused by a new one, so the entry is removed when its socket closes, and one the
// map kept anyway counts only while the local endpoint still matches.
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

// How many records EVENTS had no room for. bpf_ringbuf_reserve() returns NULL and
// bpf_ringbuf_output() an error when the reader has not emptied the ring in time, and the
// kernel keeps no count of either (__bpf_ringbuf_reserve() in kernel/bpf/ringbuf.c), so
// this is the only one. Userspace reports what it gains.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} LOST_RECORDS SEC(".maps");

static __always_inline void count_lost_record(void)
{
    __u32 key = 0;
    __u64 *value = bpf_map_lookup_elem(&LOST_RECORDS, &key);
    if (value)
        __sync_fetch_and_add(value, 1);
}

// The sequence number each TCP socket's reader had reached when its received bytes were
// last counted: tcp_sock.copied_seq, which the kernel advances by what a read takes off
// the receive queue and leaves alone for MSG_PEEK (tcp_recvmsg_locked() in
// net/ipv4/tcp.c). Keyed by the socket's kernel address, like SEND_OWNERS, and removed
// when its socket closes.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);
    __type(value, __u32);
} TCP_READ_SEQ SEC(".maps");

static __always_inline __u32 tcp_copied_seq(struct sock *sk)
{
    struct tcp_sock *tcp = (struct tcp_sock *)sk;
    return BPF_CORE_READ(tcp, copied_seq);
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

// The value bpf_get_socket_cookie() returns, read from the field it reads. kprobe and
// tracepoint programs may not call that helper: bpf-helpers(7) offers it only to socket,
// cgroup and BTF tracing programs. The kernel assigns a cookie when something first asks
// for one (sock_gen_cookie()), so this is zero until then, and userspace takes zero to
// mean "no cookie". The assign_*_cookie programs below ask, where the kernel lets them.
static __always_inline __u64 socket_cookie(struct sock *sk)
{
    return (__u64)BPF_CORE_READ(sk, __sk_common.skc_cookie.counter);
}

// The socket's local port in network byte order, read from where it outlives the socket's
// place in the port table. skc_num is the bound port, and tcp_set_state() gives a port the
// kernel chose back before it reports TCP_CLOSE: inet_put_port() ends in
// __inet_put_port(), which sets inet_num, the same field, to zero. A close record read
// from skc_num alone names port 0 and ends no flow. inet_sport keeps the port, which is why
// the kernel's own inet_sock_set_state tracepoint reports that field
// (include/trace/events/sock.h).
static __always_inline __be16 socket_local_port(struct sock *sk)
{
    __u16 bound = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (bound)
        return bpf_htons(bound);
    struct inet_sock *inet = (struct inet_sock *)sk;
    return BPF_CORE_READ(inet, inet_sport);
}

static __always_inline int fill_from_sock(
    struct wire_flow_record *record,
    struct sock *sk,
    __u8 protocol
) {
    __u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    record->protocol = protocol;
    record->pid = current_pid();
    record->timestamp = bpf_ktime_get_ns();
    // Never reused for the lifetime of the boot, so a changed cookie on an unchanged
    // tuple is proof of a new socket.
    record->cookie = socket_cookie(sk);
    record->ifindex = BPF_CORE_READ(sk, __sk_common.skc_bound_dev_if);
    record->local_port = socket_local_port(sk);
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

static __always_inline int same_local_address(
    const struct owner_seen *seen,
    const struct wire_flow_record *record
) {
    if (seen->local_port != record->local_port)
        return 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (seen->local_addr[i] != record->local_addr[i])
            return 0;
    }
    return 1;
}

// The process last seen using `sk` from one of its own system calls, or 0 when none was:
// what connect, accept or a send recorded in SEND_OWNERS.
static __always_inline __u32 recorded_owner(
    struct sock *sk,
    const struct wire_flow_record *record
) {
    __u64 socket = (__u64)sk;
    struct owner_seen *seen = bpf_map_lookup_elem(&SEND_OWNERS, &socket);
    if (seen && same_local_address(seen, record))
        return seen->pid;
    return 0;
}

// `owned_by_task` is false where the running task is not evidence of the socket's owner.
// The record then names the owner an earlier system call on the socket recorded, if any.
static __always_inline int emit_socket(
    struct sock *sk,
    struct msghdr *msg,
    __u8 protocol,
    __u8 kind,
    __u64 byte_count,
    int owned_by_task
) {
    struct wire_flow_record *record = bpf_ringbuf_reserve(&EVENTS, sizeof(*record), 0);
    if (!record) {
        count_lost_record();
        return 0;
    }
    __builtin_memset(record, 0, sizeof(*record));
    record->magic = NETMETRICS_MAGIC;
    record->version = NETMETRICS_VERSION;
    record->kind = kind;
    record->byte_count = byte_count;
    if (fill_from_sock(record, sk, protocol) != 0) {
        bpf_ringbuf_discard(record, 0);
        return 0;
    }
    if (!owned_by_task)
        record->pid = recorded_owner(sk, record);
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
    if (!record) {
        count_lost_record();
        return 0;
    }
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

// Names the process using a socket from its own system call: at connect, when accept
// returns the socket, and at sendmsg entry. The receiver can read a packet before sendmsg
// returns, so the byte record comes too late to prove who owned the endpoint when it
// arrived. The time is read before the record takes its ring position, so a record timed
// after a query's arrival is always consumed after every owner record emitted before it.
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
    __u64 socket = (__u64)sk;
    struct owner_seen *seen = bpf_map_lookup_elem(&SEND_OWNERS, &socket);
    if (seen && seen->pid == record.pid && same_local_address(seen, &record) &&
        started_at - seen->emitted_at < OWNER_REFRESH_NS)
        return;
    // The owner is not remembered either, so the next call on the socket emits it again.
    if (bpf_ringbuf_output(&EVENTS, &record, sizeof(record), 0) != 0) {
        count_lost_record();
        return;
    }
    struct owner_seen next = {
        .pid = record.pid,
        .local_port = record.local_port,
        .emitted_at = started_at,
    };
    __builtin_memcpy(next.local_addr, record.local_addr, sizeof(next.local_addr));
    bpf_map_update_elem(&SEND_OWNERS, &socket, &next, BPF_ANY);
}

// Whether a connection in `state` is established: ESTABLISHED or CLOSE_WAIT, the two
// states netmetrics_core::TcpState::is_established names, and the two the kernel counts
// in TCP_MIB_CURRESTAB (tcp_set_state() in net/ipv4/tcp.c).
static __always_inline int tcp_state_established(int state)
{
    return state == TCP_ESTABLISHED_VALUE || state == TCP_CLOSE_WAIT_VALUE;
}

// Every change of a TCP socket's state passes through this tracepoint: tcp_set_state()
// ends in inet_sk_state_store(), which fires it, as does inet_sk_set_state()
// (net/ipv4/af_inet.c). A flow follows the same three steps as the kernel's own count of
// established connections:
//
// - It opens when the socket becomes established: from SYN_SENT or SYN_RECV to
//   ESTABLISHED, or from SYN_RECV straight to CLOSE_WAIT when the peer's FIN arrives with
//   the end of a TCP Fast Open handshake.
// - It is finishing when the socket leaves both states without closing: tcp_close_state()
//   moves ESTABLISHED to FIN_WAIT1 and CLOSE_WAIT to LAST_ACK when this end sends its FIN,
//   for shutdown(SHUT_WR) and for close() alike. The socket still exists, and after a
//   shutdown it still receives.
// - It closes when the socket reaches TCP_CLOSE, from any state.
SEC("tracepoint/sock/inet_sock_set_state")
int inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != PROTO_TCP)
        return 0;
    int was_established = tcp_state_established(ctx->oldstate);
    int is_established = tcp_state_established(ctx->newstate);
    __u8 kind;
    if (is_established && !was_established)
        kind = FLOW_OPEN;
    else if (ctx->newstate == TCP_CLOSE_VALUE)
        kind = FLOW_CLOSE;
    else if (was_established && !is_established)
        kind = FLOW_FINISHING;
    else
        return 0;

    // The addresses, ports and cookie come from the socket, as in every other record, so
    // they match the byte records' keys. Reading them from the context instead would need
    // a computed offset into it, which the verifier rejects ("dereference of modified ctx
    // ptr"). TCP changes state wherever the kernel processes the socket, often in softirq
    // on the receive path, so the current task is not evidence of the owner. The record
    // names the process that connected, which trace_tcp_connect recorded. A connection
    // that is accepted has no owner yet when it is established, and its record carries
    // PID 0 until trace_inet_csk_accept, a byte probe or procfs reconciliation names one.
    struct sock *sk = (struct sock *)ctx->skaddr;
    __u64 socket = (__u64)sk;
    emit_socket(sk, NULL, PROTO_TCP, kind, 0, 0);
    if (kind == FLOW_OPEN) {
        // Nothing has been read from a connection that has just been established, so
        // its reads are counted from here (see trace_tcp_cleanup_rbuf).
        __u32 read_to = tcp_copied_seq(sk);
        bpf_map_update_elem(&TCP_READ_SEQ, &socket, &read_to, BPF_ANY);
    }
    if (kind == FLOW_CLOSE) {
        bpf_map_delete_elem(&SEND_OWNERS, &socket);
        bpf_map_delete_elem(&TCP_READ_SEQ, &socket);
    }
    return 0;
}

// tcp_v4_connect() and tcp_v6_connect() call tcp_connect() from the connect system call,
// after they have chosen the local address and port, to send the SYN.
SEC("kprobe/tcp_connect")
int BPF_KPROBE(trace_tcp_connect, struct sock *sk) {
    emit_owner(sk, PROTO_TCP);
    return 0;
}

// inet_csk_accept() returns the established socket to the accept system call.
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(trace_inet_csk_accept, struct sock *sk) {
    if (sk)
        emit_owner(sk, PROTO_TCP);
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
// tcp_sendmsg() returns int: the byte count, or a negative errno. Read as a long, the
// errno keeps its low 32 bits where the upper half of the register is clear, and a
// failed send of -ECONNRESET would count as 4,294,967,192 bytes sent.
int BPF_KRETPROBE(complete_tcp_sendmsg, int sent) {
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

// Every path that takes bytes off a TCP receive queue ends in tcp_cleanup_rbuf(sk, copied):
// recvmsg, splice and the other tcp_read_sock() readers, and zero-copy receive
// (net/ipv4/tcp.c). `copied` alone is not what the call consumed:
//
// - recvmsg passes what it copied when the read was MSG_PEEK too, and the bytes are then
//   still queued, to be read and passed again.
// - A read that waits for more data, as MSG_WAITALL and SO_RCVLOWAT make it, calls this
//   before each wait with its running total, and again at the end with the whole total.
// - Zero-copy receive passes the bytes its fallback copy already passed in a call of its
//   own.
// - Setting TCP_QUICKACK calls it with 1 to send a pending ACK, having read nothing.
//
// What the socket's reader advanced by since the last call is what was consumed: every
// one of those paths moves copied_seq before it calls this, and a peek does not move it.
// The count is the smaller of the two, because copied_seq also steps over a FIN and over
// urgent data that `copied` leaves out. The caller holds the socket's lock, so calls for
// one socket do not interleave.
//
// A socket first seen here has no position yet: it was established before the programs
// were attached, or it left the map. Its first call is counted by `copied`, as every call
// once was.
SEC("kprobe/tcp_cleanup_rbuf")
int BPF_KPROBE(trace_tcp_cleanup_rbuf, struct sock *sk, int copied) {
    __u64 socket = (__u64)sk;
    __u32 read_to = tcp_copied_seq(sk);
    __s64 consumed = copied;
    __u32 *counted_to = bpf_map_lookup_elem(&TCP_READ_SEQ, &socket);
    if (counted_to) {
        // Sequence numbers wrap, and so does their difference.
        __u32 advanced = read_to - *counted_to;
        if (advanced < consumed)
            consumed = advanced;
        *counted_to = read_to;
    } else {
        bpf_map_update_elem(&TCP_READ_SEQ, &socket, &read_to, BPF_ANY);
    }
    if (consumed <= 0)
        return 0;
    return emit_socket(sk, NULL, PROTO_TCP, FLOW_RECEIVED, consumed, 1);
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
// udp_sendmsg() returns int as well: see complete_tcp_sendmsg.
int BPF_KRETPROBE(complete_udp_sendmsg, int sent) {
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
    __u64 peeked = args->peeked;
    bpf_map_delete_elem(&UDP_RECV_ARGS, &id);
    if (copied <= 0 || peeked)
        return 0;
    return emit_socket(sk, msg, PROTO_UDP, FLOW_RECEIVED, copied, 1);
}

// udp_recvmsg() and udpv6_recvmsg() end in skb_consume_udp(sk, skb, peeking ? -err : err)
// (net/ipv4/udp.c, net/ipv6/udp.c), in the task that is reading: the length is negative
// when the read was MSG_PEEK. The datagram is then still queued, and the read that takes
// it is the one to count. Without this probe a peeked datagram is counted at each read.
SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(trace_skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len) {
    if (len >= 0)
        return 0;
    __u64 id = bpf_get_current_pid_tgid();
    struct recv_args *args = bpf_map_lookup_elem(&UDP_RECV_ARGS, &id);
    if (args && args->sk == sk)
        args->peeked = 1;
    return 0;
}

SEC("kprobe/udp_destroy_sock")
int BPF_KPROBE(trace_udp_destroy_sock, struct sock *sk) {
    __u64 socket = (__u64)sk;
    emit_socket(sk, NULL, PROTO_UDP, FLOW_CLOSE, 0, 1);
    bpf_map_delete_elem(&SEND_OWNERS, &socket);
    return 0;
}

// The three programs below make the kernel assign a socket's cookie, so that the records
// above read it instead of zero. They are BTF tracing programs, which may call
// bpf_get_socket_cookie() since Linux 5.12; each is optional, and a socket whose cookie
// nothing assigned is reported without one.
//
// Every TCP socket changes state before it carries data: to SYN_SENT in connect, or to
// ESTABLISHED when a listener's child completes its handshake.
SEC("tp_btf/inet_sock_set_state")
int BPF_PROG(assign_tcp_cookie, struct sock *sk) {
    bpf_get_socket_cookie(sk);
    return 0;
}

// UDP has no state to change, so its cookie is assigned at the first send. fentry needs a
// BPF trampoline, which not every architecture has.
SEC("fentry/udp_sendmsg")
int BPF_PROG(assign_udp_cookie, struct sock *sk) {
    bpf_get_socket_cookie(sk);
    return 0;
}

SEC("fentry/udpv6_sendmsg")
int BPF_PROG(assign_udp6_cookie, struct sock *sk) {
    bpf_get_socket_cookie(sk);
    return 0;
}

// Reports the running process: who it is (its PID, start time and name are enough to tell
// it from an earlier process with the same PID) and that it changed program or ended.
static __always_inline int emit_process(struct task_struct *task, __u8 kind)
{
    struct wire_process_record *record = bpf_ringbuf_reserve(&EVENTS, sizeof(*record), 0);
    if (!record) {
        count_lost_record();
        return 0;
    }
    __builtin_memset(record, 0, sizeof(*record));
    record->magic = NETMETRICS_MAGIC;
    record->version = NETMETRICS_VERSION;
    record->kind = kind;
    record->pid = current_pid();
    record->timestamp = bpf_ktime_get_ns();
    // /proc/<pid> describes the thread group leader, whichever thread is running.
    record->start_boottime = BPF_CORE_READ(task, group_leader, start_boottime);
    BPF_CORE_READ_STR_INTO(&record->comm, task, group_leader, comm);
    bpf_ringbuf_submit(record, 0);
    return 0;
}

// Fires once exec has replaced the program, with the new comm already set.
SEC("tracepoint/sched/sched_process_exec")
int trace_process_exec(void *ctx) {
    return emit_process((struct task_struct *)bpf_get_current_task(), PROCESS_EXEC);
}

// Fires for every exiting thread. do_exit() has by then taken the thread out of
// signal->live, so the count is zero only when the last thread of the process is exiting:
// the test do_exit() itself makes for group_dead.
SEC("tracepoint/sched/sched_process_exit")
int trace_process_exit(void *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, signal, live.counter) != 0)
        return 0;
    return emit_process(task, PROCESS_EXIT);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
