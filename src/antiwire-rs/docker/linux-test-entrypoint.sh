#!/usr/bin/env sh
set -eu

MODE="${1:-offline}"
ROOT="/src"
NETMET="packages/netmet-rs/Cargo.toml"
FIREW="packages/firew-rs/Cargo.toml"

cd "$ROOT"

# Unprivileged tests across all three workspaces. `cargo test` skips every #[ignore]d test,
# so this is the tier that must stay green regardless of container capabilities.
run_offline() {
    echo "== antiwire-rs =="
    cargo test --workspace --all-features
    echo "== netmet-rs =="
    cargo test --manifest-path "$NETMET" --workspace --all-features
    echo "== firew-rs =="
    cargo test --manifest-path "$FIREW" --workspace --all-features
}

# Privileged tests. Requires --cap-add=NET_ADMIN; without it nftables and iptables refuse the
# rule mutations these tests make, so failures here mean "missing capability", not "broken".
# Offline suites are a separate mode — CI already ran them on the host before this image.
run_live() {
    if ! capsh --print 2>/dev/null | grep -q 'cap_net_admin'; then
        echo "error: live tests need CAP_NET_ADMIN; re-run with --cap-add=NET_ADMIN" >&2
        exit 2
    fi
    echo "== firew-linux live =="
    cargo test --manifest-path "$FIREW" -p firew-linux --test live_linux \
        -- --ignored --test-threads=1 --nocapture
    echo "== firew integration live =="
    cargo test --manifest-path "$FIREW" -p firew-rs --test integration \
        --no-default-features --features linux \
        -- --ignored --test-threads=1 --nocapture
}

# Builds the CO-RE object the Linux collector loads at runtime. Needs the host's BTF, so run
# with -v /sys/kernel/btf:/sys/kernel/btf:ro. Kernels built without CONFIG_DEBUG_INFO_BTF
# cannot produce it at all.
run_ebpf() {
    if [ ! -r /sys/kernel/btf/vmlinux ]; then
        echo "error: /sys/kernel/btf/vmlinux is unreadable; mount it with" >&2
        echo "       -v /sys/kernel/btf:/sys/kernel/btf:ro" >&2
        exit 2
    fi
    echo "== netmetrics eBPF object =="
    (
        cd packages/netmet-rs/crates/netmetrics-linux/ebpf
        sh ./build.sh
        ls -l netmetrics.bpf.o dns_filter.bpf.o
    )
}

# Loads both generated eBPF objects and exercises real loopback traffic. Modern kernels need
# BPF and PERFMON; older kernels may accept SYS_ADMIN instead. The DNS packet source also needs
# NET_RAW. Docker's default seccomp profile may deny bpf(2), so the documented invocation lifts
# that profile for this isolated test container.
run_ebpf_live() {
    run_ebpf
    if ! capsh --has-p=cap_net_raw 2>/dev/null; then
        echo "error: eBPF live tests need CAP_NET_RAW" >&2
        exit 2
    fi
    if ! capsh --has-p=cap_sys_admin 2>/dev/null; then
        if ! capsh --has-p=cap_bpf 2>/dev/null || ! capsh --has-p=cap_perfmon 2>/dev/null; then
            echo "error: eBPF live tests need CAP_BPF+CAP_PERFMON or CAP_SYS_ADMIN" >&2
            exit 2
        fi
    fi
    echo "== netmetrics eBPF live =="
    NETMETRICS_BPF_OBJECT="$ROOT/packages/netmet-rs/crates/netmetrics-linux/ebpf/netmetrics.bpf.o" \
    NETMETRICS_DNS_FILTER_OBJECT="$ROOT/packages/netmet-rs/crates/netmetrics-linux/ebpf/dns_filter.bpf.o" \
        cargo test --manifest-path "$NETMET" -p netmetrics --test native_linux \
        --all-features -- --ignored --test-threads=1 --nocapture
}

case "$MODE" in
    offline)
        run_offline
        ;;
    live)
        run_live
        ;;
    ebpf)
        run_ebpf
        ;;
    ebpf-live)
        run_ebpf_live
        ;;
    all)
        run_offline
        run_live
        run_ebpf_live
        ;;
    shell)
        exec /bin/sh
        ;;
    *)
        echo "usage: $0 [offline|live|ebpf|ebpf-live|all|shell]" >&2
        exit 2
        ;;
esac
