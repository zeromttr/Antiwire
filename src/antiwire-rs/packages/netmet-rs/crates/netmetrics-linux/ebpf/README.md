# Linux eBPF object contract

`netmetrics.bpf.c` contains the CO-RE accounting programs consumed by the Aya loader.
`dns_filter.bpf.c` is a typed eBPF socket filter that rejects non-DNS traffic in the
kernel, including bounded IPv4 options and IPv6 extension-header handling. There is no
handwritten architecture-specific or classic-BPF instruction stream.
Run `./build.sh` on a Linux build host with Clang, bpftool, libbpf headers, and
kernel BTF. The script maps the build host architecture to libbpf's target
macro; cross builds can set `ARCH` explicitly to a libbpf target name. Install
the resulting object as
`/usr/lib/netmetrics/netmetrics.bpf.o`, beside the daemon executable, or point
`NETMETRICS_BPF_OBJECT` to it. Install `dns_filter.bpf.o` beside it, or point
`NETMETRICS_DNS_FILTER_OBJECT` to that file. DNS packet hints are disabled explicitly if
the verified filter cannot be loaded and attached.

- tracepoint `inet_sock_set_state` attached to `sock/inet_sock_set_state`; its open and
  close records carry PID 0, because the task running a TCP state change is not the
  socket's owner
- paired kprobe/kretprobes `trace_tcp_sendmsg`/`complete_tcp_sendmsg` and
  `trace_udp_sendmsg`/`complete_udp_sendmsg`; only positive return values are
  emitted as sent bytes. The entry probes also emit an owner record (kind 5) naming
  the sending process before the packet can be delivered, at most once per 10 s per
  socket while its owner and local endpoint are unchanged
- kprobes `trace_tcp_cleanup_rbuf`, `track_udp_recvmsg`, `trace_udp_recvmsg`,
  and `trace_udp_destroy_sock`
- ring buffer map `EVENTS`
- bounded send-context maps and `SEND_DIAGNOSTICS`, which reports map pressure
  and unmatched return probes to userspace
- LRU map `SEND_OWNERS`, which throttles owner records. Its presence tells the
  loader the object emits them; an object without it still accounts bytes, but
  endpoint ownership history stays unavailable until the object is rebuilt

Probe capabilities are attached independently. Entry/return pairs are transactional,
and the loader tries both IPv4 and IPv6 UDP symbols. Missing lifecycle probes enable
periodic procfs reconciliation; the backend falls back completely only when no byte
capability or an essential object/ring resource is available.

Every ring record must use the 64-byte `NMT1` format decoded by
`netmetrics_sys::WireFlowRecord`. Keeping the kernel program as a separately
built CO-RE artifact avoids binding the userspace crate to one kernel's
`vmlinux.h`. If loading or privilege checks fail, the backend emits explicit
`SourceUnavailable` and `SnapshotOnly` degradation events before using procfs.
