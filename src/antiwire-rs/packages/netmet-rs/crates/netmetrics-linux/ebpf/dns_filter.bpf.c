// SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause)
// Architecture-independent eBPF socket filter for UDP DNS packet capture.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define DNS_PORT 53
#define IPPROTO_UDP_VALUE 17
#define IPPROTO_HOPOPTS_VALUE 0
#define IPPROTO_ROUTING_VALUE 43
#define IPPROTO_FRAGMENT_VALUE 44
#define IPPROTO_AH_VALUE 51
#define IPPROTO_DSTOPTS_VALUE 60
#define MAX_EXTENSION_BYTES 256

static __always_inline int load_u8(struct __sk_buff *skb, __u32 offset, __u8 *value)
{
    return bpf_skb_load_bytes(skb, offset, value, sizeof(*value));
}

static __always_inline int load_be16(struct __sk_buff *skb, __u32 offset, __be16 *value)
{
    return bpf_skb_load_bytes(skb, offset, value, sizeof(*value));
}

static __always_inline int dns_ports(struct __sk_buff *skb, __u32 offset)
{
    __be16 source = 0;
    __be16 destination = 0;
    if (load_be16(skb, offset, &source) != 0 ||
        load_be16(skb, offset + 2, &destination) != 0)
        return 0;
    return source == bpf_htons(DNS_PORT) || destination == bpf_htons(DNS_PORT);
}

static __always_inline int ipv4_dns(struct __sk_buff *skb, __u8 first)
{
    __u32 header_length = (first & 0x0f) * 4;
    __u8 protocol = 0;
    __be16 fragment = 0;
    if (header_length < 20 || load_u8(skb, 9, &protocol) != 0 ||
        protocol != IPPROTO_UDP_VALUE || load_be16(skb, 6, &fragment) != 0)
        return 0;
    if ((bpf_ntohs(fragment) & 0x3fff) != 0)
        return 0;
    return dns_ports(skb, header_length);
}

static __always_inline int ipv6_dns(struct __sk_buff *skb)
{
    __u8 next = 0;
    __u32 offset = 40;
    if (load_u8(skb, 6, &next) != 0)
        return 0;

#pragma unroll
    for (int i = 0; i < 8; i++) {
        if (next == IPPROTO_UDP_VALUE)
            return dns_ports(skb, offset);
        if (offset > 40 + MAX_EXTENSION_BYTES)
            return 0;
        if (next == IPPROTO_HOPOPTS_VALUE || next == IPPROTO_ROUTING_VALUE ||
            next == IPPROTO_DSTOPTS_VALUE) {
            __u8 length = 0;
            if (load_u8(skb, offset, &next) != 0 ||
                load_u8(skb, offset + 1, &length) != 0)
                return 0;
            offset += ((__u32)length + 1) * 8;
            continue;
        }
        if (next == IPPROTO_FRAGMENT_VALUE) {
            __be16 fragment = 0;
            if (load_u8(skb, offset, &next) != 0 ||
                load_be16(skb, offset + 2, &fragment) != 0)
                return 0;
            if ((bpf_ntohs(fragment) & 0xfff9) != 0)
                return 0;
            offset += 8;
            continue;
        }
        if (next == IPPROTO_AH_VALUE) {
            __u8 length = 0;
            if (load_u8(skb, offset, &next) != 0 ||
                load_u8(skb, offset + 1, &length) != 0)
                return 0;
            offset += ((__u32)length + 2) * 4;
            continue;
        }
        return 0;
    }
    return 0;
}

SEC("socket")
int dns_packet_filter(struct __sk_buff *skb)
{
    __u8 first = 0;
    if (load_u8(skb, 0, &first) != 0)
        return 0;
    if ((first >> 4) == 4)
        return ipv4_dns(skb, first) ? skb->len : 0;
    if ((first >> 4) == 6)
        return ipv6_dns(skb) ? skb->len : 0;
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
