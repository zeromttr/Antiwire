# Linux eBPF object contract

`netmetrics.bpf.c` contains the CO-RE accounting programs consumed by the Aya loader.
`dns_filter.bpf.c` is a typed eBPF socket filter that rejects non-DNS traffic in the
kernel, passing only IP packets to or from port 53 over UDP and TCP, including bounded
IPv4 options and IPv6 extension-header handling. Its socket is opened for every protocol
(`ETH_P_ALL`), the only kind the kernel hands outgoing packets to. There is no
handwritten architecture-specific or classic-BPF instruction stream.
Run `./build.sh` on a Linux build host with Clang, bpftool, libbpf headers, and
kernel BTF. The script maps the build host architecture to libbpf's target
macro; cross builds can set `ARCH` explicitly to a libbpf target name. Install
the resulting object as
`/usr/lib/netmetrics/netmetrics.bpf.o`, beside the daemon executable, or point
`NETMETRICS_BPF_OBJECT` to it. Install `dns_filter.bpf.o` beside it, or point
`NETMETRICS_DNS_FILTER_OBJECT` to that file. DNS packet hints are disabled explicitly if
the verified filter cannot be loaded and attached.

- tracepoint `inet_sock_set_state` attached to `sock/inet_sock_set_state`. It emits an
  open record (kind 1) when a socket becomes established (`ESTABLISHED` or `CLOSE_WAIT`),
  a finishing record (kind 8) when it leaves both states without closing, which is when
  this end sends its FIN, and a close record (kind 2) when it reaches `TCP_CLOSE`. A
  finishing flow keeps its byte records until its close record. The task
  running a TCP state change is not the socket's owner, so these records
  name the process `SEND_OWNERS` holds for the socket: the one that connected. A
  connection that is accepted has none yet, and its open record carries PID 0. Every
  record's local port is the socket's bound port (`skc_num`), or `inet_sport` once the
  kernel has cleared that, which it does for a port it chose before it reports
  `TCP_CLOSE`: a close record has to name the port its flow was opened under
- paired kprobe/kretprobes `trace_tcp_sendmsg`/`complete_tcp_sendmsg` and
  `trace_udp_sendmsg`/`complete_udp_sendmsg`; only positive return values are
  emitted as sent bytes. The entry probes also emit an owner record (kind 5) naming
  the sending process before the packet can be delivered, at most once per 10 s per
  socket while its owner and local endpoint are unchanged
- kprobe `trace_tcp_connect` on `tcp_connect` and kretprobe `trace_inet_csk_accept` on
  `inet_csk_accept`, which emit the same owner record when a process connects a TCP
  socket and when accept hands it one, before the connection carries data
- kprobe `trace_tcp_cleanup_rbuf` on `tcp_cleanup_rbuf`, which every path that takes bytes
  off a TCP receive queue ends in. It emits received bytes as what the socket's reader
  (`tcp_sock.copied_seq`) advanced by since the last call, capped at the length the
  kernel passed. The length alone counts some bytes more than once: a `MSG_PEEK` read
  passes bytes that stay queued, a read that waits for more data (`MSG_WAITALL`,
  `SO_RCVLOWAT`) passes its running total before each wait, zero-copy receive passes its
  fallback copy twice, and setting `TCP_QUICKACK` passes 1 having read nothing. LRU map
  `TCP_READ_SEQ` holds each socket's last position, set when the connection is
  established and removed when it closes. A socket without one, established before the
  programs were attached, has its first call counted by the length
- paired kprobe/kretprobe `track_udp_recvmsg`/`trace_udp_recvmsg`, which emit a
  positive return value as received bytes, and kprobe `trace_skb_consume_udp` on
  `skb_consume_udp`, which the receive functions call with a negative length for a
  `MSG_PEEK` read: such a read is not counted, since its datagram stays queued for the
  read that takes it. Without that probe the pair still counts, and counts a peeked
  datagram at each read. A datagram longer than the buffer it is read into counts as the
  bytes copied, or as its full length when the read asked for it with `MSG_TRUNC`
- kprobe `trace_udp_destroy_sock`
- BTF tracing programs `assign_tcp_cookie` (`tp_btf/inet_sock_set_state`),
  `assign_udp_cookie` (`fentry/udp_sendmsg`) and `assign_udp6_cookie`
  (`fentry/udpv6_sendmsg`). They only call `bpf_get_socket_cookie()`, which makes the
  kernel assign the cookie the other programs read: kprobes may not call the helper, and
  the kernel assigns a cookie only when asked. They need Linux 5.12, and the `fentry`
  ones an architecture with BPF trampolines; a socket none of them reached is reported
  without a cookie
- tracepoints `trace_process_exec` on `sched/sched_process_exec` and `trace_process_exit`
  on `sched/sched_process_exit`, which emit a process record (kinds 6 and 7) with the
  PID, start time and name of the thread group. The exit record is emitted once per
  process, when its last thread exits
- read-only globals `LOADER_PIDNS_DEV` and `LOADER_PIDNS_INO`, the device and inode of the
  loader's `/proc/self/ns/pid`. The loader sets them only when it runs outside the initial
  PID namespace, as in a container or WSL. Every record then carries the PID that namespace
  gives the process (`bpf_get_ns_current_pid_tgid()`, Linux 5.7), which is the number the
  loader's `/proc` lists it under, and PID 0 for a process outside the namespace. Left at
  zero, records carry the kernel's own PID, which is the same number in the initial
  namespace. An object without the globals still loads and reports the kernel's PID
- ring buffer map `EVENTS`
- array map `LOST_RECORDS`, the count of records `EVENTS` had no room for. The kernel
  keeps no such count, so every program adds to this one when its reserve or output
  fails, and userspace reports what the count gains as
  `DegradeReason::BufferOverflow`. An object without the map still works; its losses
  cannot be reported, and the loader says so once
- bounded send-context maps and `SEND_DIAGNOSTICS`, which reports map pressure
  and unmatched return probes to userspace
- LRU map `SEND_OWNERS`, the last owner record of each socket. It throttles owner
  records and supplies the owner where the running task is not one, and an entry is
  removed when its socket closes. Its presence tells the loader the object emits owner
  records; an object without it still accounts bytes, but endpoint ownership history
  stays unavailable until the object is rebuilt

Probe capabilities are attached independently. Entry/return pairs are transactional,
and the loader tries both IPv4 and IPv6 UDP symbols. Missing lifecycle probes enable
periodic procfs reconciliation, and a missing exit tracepoint a periodic check of
`/proc` for processes that are gone; the backend falls back completely only when no byte
capability or an essential object/ring resource is available.

Every ring record starts with the `NMT1` magic, a version and a kind, and is decoded by
`netmetrics_sys::WireRecord`: a flow record (`WireFlowRecord`, 76 bytes at version 3) or a
process record (`WireProcessRecord`, 44 bytes). Keeping the kernel program as a separately
built CO-RE artifact avoids binding the userspace crate to one kernel's
`vmlinux.h`. If loading or privilege checks fail, the backend emits explicit
`SourceUnavailable` and `SnapshotOnly` degradation events before using procfs.
