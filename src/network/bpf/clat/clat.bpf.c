/* SPDX-License-Identifier: GPL-2.0-only */

/* eBPF TC program for CLAT (464XLAT) IPv4↔IPv6 translation.
 *
 * Attached to a physical interface's TC hooks:
 *   - Egress: translates outgoing IPv4 packets to IPv6 (CLAT → NAT64 gateway)
 *   - Ingress: translates incoming IPv6 packets to IPv4 (NAT64 gateway → CLAT)
 *
 * Translation follows RFC 6145/7915 for stateless IP/ICMP translation and
 * RFC 6052 for IPv4-embedded IPv6 address format.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "clat.h"

/* TC action return codes — not in vmlinux.h */
#define TC_ACT_OK 0

/* Ethernet header length */
#define ETH_H_LEN  14
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

/* IP header lengths */
#define IP_H_LEN   20
#define IP6_H_LEN  40
#define HDR_DIFF   (IP6_H_LEN - IP_H_LEN)

/* IPv4 flags */
#define IP_DF      0x4000
#define IP_MF      0x2000
#define IP_OFFMASK 0x1FFF

/* ICMP types */
#define ICMP_ECHOREPLY     0
#define ICMP_DEST_UNREACH  3
#define ICMP_ECHO          8
#define ICMP_TIME_EXCEEDED 11
#define ICMP_FRAG_NEEDED   4

/* ICMPv6 types */
#define ICMPV6_DEST_UNREACH  1
#define ICMPV6_PKT_TOOBIG    2
#define ICMPV6_TIME_EXCEED   3
#define ICMPV6_ECHO_REQUEST  128
#define ICMPV6_ECHO_REPLY    129
#define ICMPV6_NOROUTE       0
#define ICMPV6_ADM_PROHIBITED 1
#define ICMPV6_ADDR_UNREACH  3
#define ICMPV6_PORT_UNREACH  4

/* IPPROTO_ICMPV6 is not in all vmlinux.h versions */
#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58
#endif

/* volatile to prevent compiler from optimizing out BSS data that
 * userspace writes to before the program runs. Cast away volatile
 * when passing to helpers via the cfg() accessor. */
volatile struct clat_config clat_cfg = {};

#define cfg() ((struct clat_config *)&clat_cfg)

/* Helper: ensure we can safely read a header at the given offset */
#define ensure_header(hdr, skb, data, data_end, offset)           \
        ({                                                        \
                *(hdr) = (void *)(long)(*(data)) + (offset);      \
                (void *)(*(hdr) + 1) <= (void *)(long)(*(data_end)); \
        })

/* RFC 6052: Embed IPv4 address (4 bytes) into PREF64 prefix to form IPv6 address (16 bytes) */
static __always_inline void v4addr_to_v6(
                const __u8 *prefix,
                unsigned plen,
                const __u8 *v4,
                __u8 *v6) {

        __builtin_memcpy(v6, prefix, 16);

        switch (plen) {
        case 96:
                v6[12] = v4[0]; v6[13] = v4[1]; v6[14] = v4[2]; v6[15] = v4[3];
                break;
        case 64:
                v6[9] = v4[0]; v6[10] = v4[1]; v6[11] = v4[2]; v6[12] = v4[3];
                v6[8] = 0;
                break;
        case 56:
                v6[7] = v4[0]; v6[9] = v4[1]; v6[10] = v4[2]; v6[11] = v4[3];
                v6[8] = 0;
                break;
        case 48:
                v6[6] = v4[0]; v6[7] = v4[1]; v6[9] = v4[2]; v6[10] = v4[3];
                v6[8] = 0;
                break;
        case 40:
                v6[5] = v4[0]; v6[6] = v4[1]; v6[7] = v4[2]; v6[9] = v4[3];
                v6[8] = 0;
                break;
        case 32:
                v6[4] = v4[0]; v6[5] = v4[1]; v6[6] = v4[2]; v6[7] = v4[3];
                v6[8] = 0;
                break;
        }
}

/* RFC 6052: Extract IPv4 address from PREF64-mapped IPv6 address */
static __always_inline void v6addr_to_v4(
                const __u8 *v6,
                unsigned plen,
                __u8 *v4) {

        switch (plen) {
        case 96:
                v4[0] = v6[12]; v4[1] = v6[13]; v4[2] = v6[14]; v4[3] = v6[15];
                break;
        case 64:
                v4[0] = v6[9]; v4[1] = v6[10]; v4[2] = v6[11]; v4[3] = v6[12];
                break;
        case 56:
                v4[0] = v6[7]; v4[1] = v6[9]; v4[2] = v6[10]; v4[3] = v6[11];
                break;
        case 48:
                v4[0] = v6[6]; v4[1] = v6[7]; v4[2] = v6[9]; v4[3] = v6[10];
                break;
        case 40:
                v4[0] = v6[5]; v4[1] = v6[6]; v4[2] = v6[7]; v4[3] = v6[9];
                break;
        case 32:
                v4[0] = v6[4]; v4[1] = v6[5]; v4[2] = v6[6]; v4[3] = v6[7];
                break;
        }
}

/* Check if IPv6 address src (16 bytes at given skb offset) matches PREF64 prefix */
static __always_inline bool addr_in_pref64(struct __sk_buff *skb, unsigned offset) {
        __u8 addr[16];

        if (bpf_skb_load_bytes(skb, offset, addr, 16) < 0)
                return false;

        unsigned prefix_bytes = cfg()->pref64_len / 8;
        for (unsigned i = 0; i < prefix_bytes && i < 16; i++) {
                if (addr[i] != cfg()->pref64[i])
                        return false;
        }
        return true;
}

/* Check if IPv6 address at skb offset matches our local IPv6 address */
static __always_inline bool addr_is_local_v6(struct __sk_buff *skb, unsigned offset) {
        __u8 addr[16];

        if (bpf_skb_load_bytes(skb, offset, addr, 16) < 0)
                return false;

        for (int i = 0; i < 16; i++) {
                if (addr[i] != cfg()->local_v6[i])
                        return false;
        }
        return true;
}

/* Translate ICMP type/code to ICMPv6 (4→6) */
static __always_inline int translate_icmp_4to6(struct __sk_buff *skb, unsigned l4_off) {
        __u8 type, code, new_type, new_code;

        if (bpf_skb_load_bytes(skb, l4_off, &type, 1) < 0)
                return -1;
        if (bpf_skb_load_bytes(skb, l4_off + 1, &code, 1) < 0)
                return -1;

        switch (type) {
        case ICMP_ECHO:
                new_type = ICMPV6_ECHO_REQUEST;
                new_code = 0;
                break;
        case ICMP_ECHOREPLY:
                new_type = ICMPV6_ECHO_REPLY;
                new_code = 0;
                break;
        case ICMP_DEST_UNREACH:
                switch (code) {
                case 0: case 1:
                        new_type = ICMPV6_DEST_UNREACH;
                        new_code = ICMPV6_NOROUTE;
                        break;
                case 3:
                        new_type = ICMPV6_DEST_UNREACH;
                        new_code = ICMPV6_PORT_UNREACH;
                        break;
                case ICMP_FRAG_NEEDED:
                {
                        __be16 mtu16;
                        __u32 mtu;

                        new_type = ICMPV6_PKT_TOOBIG;
                        new_code = 0;
                        if (bpf_skb_load_bytes(skb, l4_off + 6, &mtu16, 2) < 0)
                                return -1;
                        mtu = bpf_ntohs(mtu16) + HDR_DIFF;
                        if (mtu < 1280)
                                mtu = 1280;
                        __be32 mtu32 = bpf_htonl(mtu);
                        bpf_skb_store_bytes(skb, l4_off + 4, &mtu32, 4, 0);
                        break;
                }
                case 9: case 10: case 13:
                        new_type = ICMPV6_DEST_UNREACH;
                        new_code = ICMPV6_ADM_PROHIBITED;
                        break;
                default:
                        return -1;
                }
                break;
        case ICMP_TIME_EXCEEDED:
                new_type = ICMPV6_TIME_EXCEED;
                new_code = code;
                break;
        default:
                return -1;
        }

        bpf_skb_store_bytes(skb, l4_off, &new_type, 1, 0);
        bpf_skb_store_bytes(skb, l4_off + 1, &new_code, 1, 0);
        return 0;
}

/* Translate ICMPv6 type/code to ICMP (6→4) */
static __always_inline int translate_icmp_6to4(struct __sk_buff *skb, unsigned l4_off) {
        __u8 type, code, new_type, new_code;

        if (bpf_skb_load_bytes(skb, l4_off, &type, 1) < 0)
                return -1;
        if (bpf_skb_load_bytes(skb, l4_off + 1, &code, 1) < 0)
                return -1;

        switch (type) {
        case ICMPV6_ECHO_REQUEST:
                new_type = ICMP_ECHO;
                new_code = 0;
                break;
        case ICMPV6_ECHO_REPLY:
                new_type = ICMP_ECHOREPLY;
                new_code = 0;
                break;
        case ICMPV6_DEST_UNREACH:
                new_type = ICMP_DEST_UNREACH;
                switch (code) {
                case ICMPV6_NOROUTE: case ICMPV6_ADDR_UNREACH:
                        new_code = 1;
                        break;
                case ICMPV6_ADM_PROHIBITED:
                        new_code = 13;
                        break;
                case ICMPV6_PORT_UNREACH:
                        new_code = 3;
                        break;
                default:
                        return -1;
                }
                break;
        case ICMPV6_PKT_TOOBIG:
        {
                __be32 mtu32;
                __u32 mtu;

                new_type = ICMP_DEST_UNREACH;
                new_code = ICMP_FRAG_NEEDED;
                if (bpf_skb_load_bytes(skb, l4_off + 4, &mtu32, 4) < 0)
                        return -1;
                mtu = bpf_ntohl(mtu32);
                if (mtu > HDR_DIFF)
                        mtu -= HDR_DIFF;
                if (mtu > 0xFFFF)
                        return -1;
                __be16 mtu16 = bpf_htons((__u16)mtu);
                bpf_skb_store_bytes(skb, l4_off + 6, &mtu16, 2, 0);
                break;
        }
        case ICMPV6_TIME_EXCEED:
                new_type = ICMP_TIME_EXCEEDED;
                new_code = code;
                break;
        default:
                return -1;
        }

        bpf_skb_store_bytes(skb, l4_off, &new_type, 1, 0);
        bpf_skb_store_bytes(skb, l4_off + 1, &new_code, 1, 0);
        return 0;
}

/* Egress: IPv4 → IPv6 translation */
SEC("tcx/egress")
int clat_egress(struct __sk_buff *skb) {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct ethhdr *eth;
        struct iphdr *ip4;
        __u8 src6[16], dst6[16];
        __u8 protocol, tos, ttl;
        __be16 tot_len, payload_len;
        unsigned l4_off;

        if (!ensure_header(&eth, skb, &data, &data_end, 0))
                return TC_ACT_OK;
        if (eth->h_proto != bpf_htons(ETH_P_IP))
                return TC_ACT_OK;
        if (!ensure_header(&ip4, skb, &data, &data_end, ETH_H_LEN))
                return TC_ACT_OK;

        /* Only translate packets from our CLAT IPv4 address */
        if (__builtin_memcmp(&ip4->saddr, cfg()->local_v4, 4) != 0)
                return TC_ACT_OK;

        /* Only handle standard 20-byte IPv4 headers (no options) */
        if (ip4->ihl != 5)
                return TC_ACT_OK;

        /* Reject fragmented packets */
        if (bpf_ntohs(ip4->frag_off) & (IP_MF | IP_OFFMASK))
                return TC_ACT_OK;

        protocol = ip4->protocol;
        if (protocol != IPPROTO_TCP &&
            protocol != IPPROTO_UDP &&
            protocol != IPPROTO_ICMP)
                return TC_ACT_OK;

        tos = ip4->tos;
        ttl = ip4->ttl;
        tot_len = ip4->tot_len;
        payload_len = bpf_htons(bpf_ntohs(tot_len) - IP_H_LEN);

        /* Build IPv6 addresses */
        __builtin_memcpy(src6, cfg()->local_v6, 16);
        v4addr_to_v6(cfg()->pref64, cfg()->pref64_len,
                     (const __u8 *)&ip4->daddr, dst6);

        l4_off = ETH_H_LEN + IP_H_LEN;

        /* Handle ICMP translation before header adjustment */
        if (protocol == IPPROTO_ICMP) {
                if (translate_icmp_4to6(skb, l4_off) < 0)
                        return TC_ACT_OK;
                /* Zero ICMP checksum */
                __be16 zero = 0;
                bpf_skb_store_bytes(skb, l4_off + 2, &zero, 2, 0);
        }

        /* Grow packet by 20 bytes for IPv6 header */
        if (bpf_skb_adjust_room(skb, HDR_DIFF, BPF_ADJ_ROOM_MAC,
                                BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
                return TC_ACT_OK;

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        /* Update Ethernet protocol */
        if (!ensure_header(&eth, skb, &data, &data_end, 0))
                return TC_ACT_OK;
        eth->h_proto = bpf_htons(ETH_P_IPV6);

        /* Write IPv6 header */
        struct {
                __be32 flow;
                __be16 plen;
                __u8   nxt;
                __u8   hlim;
        } ip6h;

        ip6h.flow = bpf_htonl((__u32)6 << 28 | (__u32)tos << 20);
        ip6h.plen = payload_len;
        ip6h.nxt = (protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : protocol;
        ip6h.hlim = ttl;

        bpf_skb_store_bytes(skb, ETH_H_LEN, &ip6h, sizeof(ip6h), 0);
        bpf_skb_store_bytes(skb, ETH_H_LEN + 8, src6, 16, 0);
        bpf_skb_store_bytes(skb, ETH_H_LEN + 24, dst6, 16, 0);

        /* Fix L4 checksums */
        l4_off = ETH_H_LEN + IP6_H_LEN;

        if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                /* Compute pseudo-header delta: IPv4 → IPv6 */
                struct { __be32 s; __be32 d; __u8 z; __u8 p; __be16 l; } ph4;
                struct { __u8 s[16]; __u8 d[16]; __be32 l; __u8 z[3]; __u8 n; } ph6;

                __builtin_memcpy(&ph4.s, cfg()->local_v4, 4);
                v6addr_to_v4(dst6, cfg()->pref64_len, (__u8 *)&ph4.d);
                ph4.z = 0;
                ph4.p = protocol;
                ph4.l = payload_len;

                __builtin_memcpy(ph6.s, src6, 16);
                __builtin_memcpy(ph6.d, dst6, 16);
                ph6.l = bpf_htonl(bpf_ntohs(payload_len));
                __builtin_memset(ph6.z, 0, 3);
                ph6.n = protocol;

                __s64 delta = bpf_csum_diff((__be32 *)&ph4, sizeof(ph4),
                                            (__be32 *)&ph6, sizeof(ph6), 0);

                unsigned coff = l4_off + (protocol == IPPROTO_TCP ? 16 : 6);

                /* Do NOT use BPF_F_MARK_MANGLED_0 on egress: IPv6 requires a valid
                 * UDP checksum (RFC 8200 §8.1). If the IPv4 UDP checksum was 0
                 * ("not computed"), the differential update would produce 0, which
                 * is invalid in IPv6. */
                bpf_l4_csum_replace(skb, coff, 0, delta, BPF_F_PSEUDO_HDR);

                /* Per RFC 768, a computed zero UDP checksum must be sent as 0xFFFF */
                if (protocol == IPPROTO_UDP) {
                        __be16 csum;
                        if (bpf_skb_load_bytes(skb, coff, &csum, 2) == 0 && csum == 0) {
                                csum = 0xFFFF;
                                bpf_skb_store_bytes(skb, coff, &csum, 2, 0);
                        }
                }

        } else if (protocol == IPPROTO_ICMP) {
                /* ICMPv6 needs pseudo-header in checksum; ICMP doesn't.
                 * Add the pseudo-header contribution to the zeroed checksum. */
                struct { __u8 s[16]; __u8 d[16]; __be32 l; __u8 z[3]; __u8 n; } ph6;

                __builtin_memcpy(ph6.s, src6, 16);
                __builtin_memcpy(ph6.d, dst6, 16);
                ph6.l = bpf_htonl(bpf_ntohs(payload_len));
                __builtin_memset(ph6.z, 0, 3);
                ph6.n = IPPROTO_ICMPV6;

                __s64 ph_csum = bpf_csum_diff(NULL, 0, (__be32 *)&ph6, sizeof(ph6), 0);
                bpf_l4_csum_replace(skb, l4_off + 2, 0, ph_csum, BPF_F_PSEUDO_HDR);
        }

        skb->protocol = bpf_htons(ETH_P_IPV6);
        return bpf_redirect(skb->ifindex, 0);
}

/* Ingress: IPv6 → IPv4 translation */
SEC("tcx/ingress")
int clat_ingress(struct __sk_buff *skb) {
        void *data = (void *)(long)skb->data;
        void *data_end = (void *)(long)skb->data_end;
        struct ethhdr *eth;
        struct ipv6hdr *ip6;
        __u8 nexthdr, tos, hop_limit;
        __be16 payload_len;
        __u8 src4[4], dst4[4];
        __u8 src6_bytes[16];
        unsigned l4_off;

        if (!ensure_header(&eth, skb, &data, &data_end, 0))
                return TC_ACT_OK;
        if (eth->h_proto != bpf_htons(ETH_P_IPV6))
                return TC_ACT_OK;
        if (!ensure_header(&ip6, skb, &data, &data_end, ETH_H_LEN))
                return TC_ACT_OK;

        /* Only translate packets to our CLAT IPv6 address */
        if (!addr_is_local_v6(skb, ETH_H_LEN + 24))
                return TC_ACT_OK;

        /* Only translate packets from PREF64 prefix */
        if (!addr_in_pref64(skb, ETH_H_LEN + 8))
                return TC_ACT_OK;

        nexthdr = ip6->nexthdr;
        if (nexthdr != IPPROTO_TCP &&
            nexthdr != IPPROTO_UDP &&
            nexthdr != IPPROTO_ICMPV6)
                return TC_ACT_OK;

        payload_len = ip6->payload_len;
        tos = (bpf_ntohl(*(__be32 *)ip6) >> 20) & 0xFF;
        hop_limit = ip6->hop_limit;

        /* Save source IPv6 for checksum and extract IPv4 addresses */
        bpf_skb_load_bytes(skb, ETH_H_LEN + 8, src6_bytes, 16);
        v6addr_to_v4(src6_bytes, cfg()->pref64_len, src4);
        __builtin_memcpy(dst4, cfg()->local_v4, 4);

        l4_off = ETH_H_LEN + IP6_H_LEN;

        /* Handle ICMPv6 translation */
        if (nexthdr == IPPROTO_ICMPV6) {
                if (translate_icmp_6to4(skb, l4_off) < 0)
                        return TC_ACT_OK;
                __be16 zero = 0;
                bpf_skb_store_bytes(skb, l4_off + 2, &zero, 2, 0);
        }

        /* Shrink packet by 20 bytes */
        if (bpf_skb_adjust_room(skb, -HDR_DIFF, BPF_ADJ_ROOM_MAC,
                                BPF_F_ADJ_ROOM_FIXED_GSO) < 0)
                return TC_ACT_OK;

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        if (!ensure_header(&eth, skb, &data, &data_end, 0))
                return TC_ACT_OK;
        eth->h_proto = bpf_htons(ETH_P_IP);

        /* Write IPv4 header */
        struct iphdr ip4h = {
                .version  = 4,
                .ihl      = 5,
                .tos      = tos,
                .tot_len  = bpf_htons(IP_H_LEN + bpf_ntohs(payload_len)),
                .id       = 0,
                .frag_off = bpf_htons(IP_DF),
                .ttl      = hop_limit,
                .protocol = (nexthdr == IPPROTO_ICMPV6) ? IPPROTO_ICMP : nexthdr,
                .check    = 0,
        };
        __builtin_memcpy(&ip4h.saddr, src4, 4);
        __builtin_memcpy(&ip4h.daddr, dst4, 4);

        /* Compute IPv4 header checksum with proper fold */
        __s64 hdr_csum = bpf_csum_diff(NULL, 0, (__be32 *)&ip4h, sizeof(ip4h), 0);
        __u32 sum = (__u32)(hdr_csum & 0xFFFFFFFF);
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        ip4h.check = (__be16)~sum;

        bpf_skb_store_bytes(skb, ETH_H_LEN, &ip4h, sizeof(ip4h), 0);

        /* Fix L4 checksums */
        l4_off = ETH_H_LEN + IP_H_LEN;

        if (nexthdr == IPPROTO_TCP || nexthdr == IPPROTO_UDP) {
                /* Pseudo-header delta: IPv6 → IPv4 */
                struct { __u8 s[16]; __u8 d[16]; __be32 l; __u8 z[3]; __u8 n; } ph6;
                struct { __be32 s; __be32 d; __u8 z; __u8 p; __be16 l; } ph4;

                /* Reconstruct original IPv6 pseudo-header */
                __builtin_memcpy(ph6.s, src6_bytes, 16);
                __builtin_memcpy(ph6.d, cfg()->local_v6, 16);
                ph6.l = bpf_htonl(bpf_ntohs(payload_len));
                __builtin_memset(ph6.z, 0, 3);
                ph6.n = nexthdr;

                __builtin_memcpy(&ph4.s, src4, 4);
                __builtin_memcpy(&ph4.d, dst4, 4);
                ph4.z = 0;
                ph4.p = nexthdr;
                ph4.l = payload_len;

                __s64 delta = bpf_csum_diff((__be32 *)&ph6, sizeof(ph6),
                                            (__be32 *)&ph4, sizeof(ph4), 0);

                unsigned coff = l4_off + (nexthdr == IPPROTO_TCP ? 16 : 6);
                __u32 flags = (nexthdr == IPPROTO_UDP) ? BPF_F_MARK_MANGLED_0 : 0;
                bpf_l4_csum_replace(skb, coff, 0, delta, flags | BPF_F_PSEUDO_HDR);

        } else if (nexthdr == IPPROTO_ICMPV6) {
                /* Remove pseudo-header contribution from ICMPv6 → ICMP */
                struct { __u8 s[16]; __u8 d[16]; __be32 l; __u8 z[3]; __u8 n; } ph6;

                __builtin_memcpy(ph6.s, src6_bytes, 16);
                __builtin_memcpy(ph6.d, cfg()->local_v6, 16);
                ph6.l = bpf_htonl(bpf_ntohs(payload_len));
                __builtin_memset(ph6.z, 0, 3);
                ph6.n = IPPROTO_ICMPV6;

                __s64 neg_ph = bpf_csum_diff((__be32 *)&ph6, sizeof(ph6), NULL, 0, 0);
                bpf_l4_csum_replace(skb, l4_off + 2, 0, neg_ph, BPF_F_PSEUDO_HDR);
        }

        skb->protocol = bpf_htons(ETH_P_IP);
        return bpf_redirect(skb->ifindex, BPF_F_INGRESS);
}

char _license[] SEC("license") = "GPL";
