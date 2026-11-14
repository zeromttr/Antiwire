#!/usr/bin/env sh
set -eu

: "${CLANG:=clang}"

if [ -z "${ARCH:-}" ]; then
  case "$(uname -m)" in
    x86_64|i386|i686) ARCH=x86 ;;
    aarch64|arm64) ARCH=arm64 ;;
    armv7*|armv8l) ARCH=arm ;;
    ppc64|ppc64le) ARCH=powerpc ;;
    s390x) ARCH=s390 ;;
    riscv64) ARCH=riscv ;;
    mips*) ARCH=mips ;;
    *)
      echo "unsupported build architecture: $(uname -m); set ARCH to a libbpf target name" >&2
      exit 2
      ;;
  esac
fi

if [ ! -f vmlinux.h ]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
fi

MULTIARCH="$("${CC:-cc}" -print-multiarch 2>/dev/null || true)"
MULTIARCH_INCLUDE=""
if [ -n "$MULTIARCH" ] && [ -d "/usr/include/$MULTIARCH" ]; then
  MULTIARCH_INCLUDE="-I/usr/include/$MULTIARCH"
fi

# shellcheck disable=SC2086
"$CLANG" \
  -g -O2 -target bpf \
  -D"__TARGET_ARCH_${ARCH}" \
  -I. \
  -I/usr/include \
  $MULTIARCH_INCLUDE \
  -c netmetrics.bpf.c \
  -o netmetrics.bpf.o

"$CLANG" \
  -g -O2 -target bpf \
  -D"__TARGET_ARCH_${ARCH}" \
  -I. \
  -I/usr/include \
  $MULTIARCH_INCLUDE \
  -c dns_filter.bpf.c \
  -o dns_filter.bpf.o
