/* SPDX-License-Identifier: GPL-2.0-only */

/* eBPF TC program for CLAT (464XLAT) IPv4↔IPv6 translation.
 *
 * Attached to a physical interface's TC hooks:
 *   - Egress: translates outgoing IPv4 packets to IPv6 (CLAT → NAT64 gateway)
 *   - Ingress: translates incoming IPv6 packets to IPv4 (NAT64 gateway → CLAT)
 *
 * Translation follows RFC 6145/7915 for stateless IP/ICMP translation and
 * RFC 6052 for IPv4-embedded IPv6 address format.
 *
 * Requires a kernel with TCX (6.6) and bpf_redirect_neigh() (5.10).
 *
 * Limitations: TCP, UDP and ICMP Echo are translated. ICMP error messages are not, since they carry
 * an embedded IP header that would have to be translated too (RFC 7915 section 4.2), which cannot
 * be done with the packet helpers available to TC programs. They are passed on unmodified.
 * Fragmented packets and IPv4 options are not translated either.
 */

#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "clat.h"

/* TC action return codes — not in vmlinux.h */
#define TC_ACT_OK 0
#define TC_ACT_SHOT 2

/* Ethernet header length */
#define ETH_H_LEN  14
#define ETH_P_IP   0x0800
#define ETH_P_IPV6 0x86DD

/* IP header lengths */
#define IP_H_LEN   20
#define IP6_H_LEN  40

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
 * when passing to helpers via the cfg() accessor.
 *
 * The type is anonymous on purpose: the generated skeleton then defines it inline instead of referring
 * to a struct from a header, like for the variables of the other BPF programs. */
volatile struct {
        CLAT_CONFIG_FIELDS
} clat_cfg = {};

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
        default:
                /* Not reachable: networkd only accepts the prefix lengths of RFC 6052. */
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
        default:
                /* Not reachable: networkd only accepts the prefix lengths of RFC 6052. */
                break;
        }
}

/* Check if IPv6 address src (16 bytes at given skb offset) matches PREF64 prefix */
static __always_inline bool addr_in_pref64(struct __sk_buff *skb, unsigned offset) {
        __u8 addr[16];

        if (bpf_skb_load_bytes(skb, offset, addr, 16) < 0)
                return false;

        unsigned prefix_bytes = cfg()->pref64_len / 8;
        if (prefix_bytes > 12) /* max valid: /96 = 12 bytes */
                prefix_bytes = 12;
        /* The bound comes from a value userspace writes after the program was compiled, so it is not
         * known to the verifier. Capping the counter with a constant keeps the loop provably finite;
         * loops with such bounds need kernel 5.3 or later, which TCX (6.6) implies anyway. */
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

/* Translate ICMP Echo type to ICMPv6 Echo type (4→6).
 * Only Echo Request/Reply are translated. ICMP error messages contain an
 * embedded inner IP header that would also need translation (RFC 7915 Section 4.2),
 * which is too complex for BPF. Error messages are dropped (return -1). */
static __always_inline int translate_icmp_4to6(struct __sk_buff *skb, unsigned l4_off) {
        __u8 type, new_type;

        if (bpf_skb_load_bytes(skb, l4_off, &type, 1) < 0)
                return -1;

        switch (type) {
        case ICMP_ECHO:
                new_type = ICMPV6_ECHO_REQUEST;
                break;
        case ICMP_ECHOREPLY:
                new_type = ICMPV6_ECHO_REPLY;
                break;
        default:
                return -1;
        }

        bpf_skb_store_bytes(skb, l4_off, &new_type, 1, 0);
        return 0;
}

/* Translate ICMPv6 Echo type to ICMP Echo type (6→4).
 * Only Echo Request/Reply are translated. See translate_icmp_4to6 comment. */
static __always_inline int translate_icmp_6to4(struct __sk_buff *skb, unsigned l4_off) {
        __u8 type, new_type;

        if (bpf_skb_load_bytes(skb, l4_off, &type, 1) < 0)
                return -1;

        switch (type) {
        case ICMPV6_ECHO_REQUEST:
                new_type = ICMP_ECHO;
                break;
        case ICMPV6_ECHO_REPLY:
                new_type = ICMP_ECHOREPLY;
                break;
        default:
                return -1;
        }

        bpf_skb_store_bytes(skb, l4_off, &new_type, 1, 0);
        return 0;
}

#define CSUM_CHUNK      128
#define CSUM_MAX_CHUNKS 12      /* 12 * 128 = 1536 bytes, enough for a UDP datagram in a 1500 byte MTU */

/* Sum the 16-bit words of len bytes of the packet starting at off, as bpf_csum_diff() does (unfolded,
 * not inverted). The packet is read in chunks, since bpf_csum_diff() only reads from the stack. Returns
 * a negative value if the data does not fit or cannot be read. */
static __noinline __s64 payload_csum(struct __sk_buff *skb, __u32 off, __u32 len) {
        __u8 buf[CSUM_CHUNK];
        __s64 sum = 0;

        for (int i = 0; i < CSUM_MAX_CHUNKS; i++) {
                /* 64 bit, so that the compiler does not zero-extend a copy for the checks below, which
                 * would leave the verifier with no bounds on the register used as the size argument. */
                __u64 n, n4;

                if (len == 0)
                        return sum;

                n = len < CSUM_CHUNK ? len : CSUM_CHUNK;
                /* Redundant, but the verifier needs to see the bounds on the size. The barrier keeps the
                 * compiler from proving the check redundant and dropping it. */
                barrier_var(n);
                if (n == 0)
                        return -1;
                barrier_var(n);         /* keep the two checks from being merged into one */
                if (n > CSUM_CHUNK)
                        return -1;

                /* bpf_csum_diff() needs a multiple of 4 bytes: zero the padding. */
                __builtin_memset(buf, 0, sizeof(buf));
                if (bpf_skb_load_bytes(skb, off, buf, n) < 0)
                        return -1;

                /* Round up to a multiple of 4. The verifier's range tracking is too coarse to see that this
                 * stays within the buffer, so bound it explicitly. */
                n4 = (n + 3) & ~3ULL;
                barrier_var(n4);
                if (n4 == 0)
                        return -1;
                barrier_var(n4);
                if (n4 > CSUM_CHUNK)
                        return -1;

                sum = bpf_csum_diff(NULL, 0, (__be32 *)buf, n4, sum);
                if (sum < 0)
                        return sum;

                off += n;
                len -= n;
        }

        return len == 0 ? sum : -1;
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

        /* IPv6 does not allow a zero UDP checksum (RFC 8200 section 8.1), while IPv4 does ("not
         * computed"). In that case there is nothing to update incrementally: sum up the datagram now,
         * while the packet is still untouched, and finish the checksum once the IPv6 pseudo-header is
         * known (RFC 7915 section 4.5). */
        bool udp_zero_csum = false;
        __s64 udp_sum = 0;

        if (protocol == IPPROTO_UDP) {
                __be16 udp_csum;

                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP_H_LEN + 6, &udp_csum, 2) < 0)
                        return TC_ACT_OK;

                if (udp_csum == 0) {
                        udp_zero_csum = true;
                        udp_sum = payload_csum(skb, ETH_H_LEN + IP_H_LEN,
                                               bpf_ntohs(ip4->tot_len) - IP_H_LEN);
                        if (udp_sum < 0)
                                return TC_ACT_OK;
                }
        }

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
                /* Read original type+code as 16-bit value for checksum delta */
                __be16 old_tc;
                if (bpf_skb_load_bytes(skb, l4_off, &old_tc, 2) < 0)
                        return TC_ACT_OK;

                if (translate_icmp_4to6(skb, l4_off) < 0)
                        return TC_ACT_OK;

                /* Read new type+code after translation. The type was rewritten already, so do not
                 * let a half-translated packet pass on failure. */
                __be16 new_tc;
                if (bpf_skb_load_bytes(skb, l4_off, &new_tc, 2) < 0)
                        return TC_ACT_SHOT;

                /* Incrementally update the checksum for the type byte change.
                 * Do NOT zero the checksum — it contains the payload checksum state.
                 * ICMPv6 pseudo-header contribution will be added after room adjustment. */
                if (bpf_l4_csum_replace(skb, l4_off + 2, old_tc, new_tc, 2) < 0)
                        return TC_ACT_SHOT;
        }

        /* Turn the skb into an IPv6 one. This grows the packet by 20 bytes for the IPv6 header
         * and updates skb->protocol, which TC programs cannot write directly. The new headers
         * are filled in below. */
        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0)
                return protocol == IPPROTO_ICMP ? TC_ACT_SHOT : TC_ACT_OK;

        /* From here on the packet is modified: drop it rather than pass a broken one on. */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        /* Update Ethernet protocol */
        if (!ensure_header(&eth, skb, &data, &data_end, 0))
                return TC_ACT_SHOT;
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

        if (bpf_skb_store_bytes(skb, ETH_H_LEN, &ip6h, sizeof(ip6h), 0) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN + 8, src6, 16, 0) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN + 24, dst6, 16, 0) < 0)
                return TC_ACT_SHOT;

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

                unsigned coff = l4_off + (protocol == IPPROTO_TCP ? 16 : 6);

                if (udp_zero_csum) {
                        /* The IPv4 datagram had no checksum: finish the sum over the datagram that was
                         * started before the translation with the IPv6 pseudo-header. */
                        __u64 total = (__u64)udp_sum +
                                      (__u64)bpf_csum_diff(NULL, 0, (__be32 *)&ph6, sizeof(ph6), 0);
                        __be16 csum;

                        total = (total & 0xffffffff) + (total >> 32);
                        total = (total & 0xffff) + (total >> 16);
                        total = (total & 0xffff) + (total >> 16);

                        /* A computed zero is sent as 0xFFFF (RFC 768) */
                        csum = (__be16)~total;
                        if (csum == 0)
                                csum = 0xFFFF;

                        if (bpf_skb_store_bytes(skb, coff, &csum, 2, 0) < 0)
                                return TC_ACT_SHOT;
                } else {
                        __s64 delta = bpf_csum_diff((__be32 *)&ph4, sizeof(ph4),
                                                    (__be32 *)&ph6, sizeof(ph6), 0);

                        if (bpf_l4_csum_replace(skb, coff, 0, delta, BPF_F_PSEUDO_HDR) < 0)
                                return TC_ACT_SHOT;

                        /* IPv6 requires valid UDP checksum; zero means 0xFFFF (RFC 768) */
                        if (protocol == IPPROTO_UDP) {
                                __be16 csum;
                                if (bpf_skb_load_bytes(skb, coff, &csum, 2) < 0)
                                        return TC_ACT_SHOT;
                                if (csum == 0) {
                                        csum = 0xFFFF;
                                        if (bpf_skb_store_bytes(skb, coff, &csum, 2, 0) < 0)
                                                return TC_ACT_SHOT;
                                }
                        }
                }

        } else if (protocol == IPPROTO_ICMP) {
                /* ICMPv6 needs pseudo-header in checksum; ICMP doesn't.
                 * Add the pseudo-header contribution to the existing checksum
                 * (which already includes payload and the updated type byte). */
                struct { __u8 s[16]; __u8 d[16]; __be32 l; __u8 z[3]; __u8 n; } ph6;

                __builtin_memcpy(ph6.s, src6, 16);
                __builtin_memcpy(ph6.d, dst6, 16);
                ph6.l = bpf_htonl(bpf_ntohs(payload_len));
                __builtin_memset(ph6.z, 0, 3);
                ph6.n = IPPROTO_ICMPV6;

                __s64 ph_csum = bpf_csum_diff(NULL, 0, (__be32 *)&ph6, sizeof(ph6), 0);
                if (bpf_l4_csum_replace(skb, l4_off + 2, 0, ph_csum, BPF_F_PSEUDO_HDR) < 0)
                        return TC_ACT_SHOT;
        }

        /* The destination of the original packet was the placeholder neighbour of the IPv4 gateway. Send
         * the translated packet through the IPv6 neighbour subsystem, which looks up the route and next
         * hop for the NAT64 address and fills in the Ethernet addresses. */
        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
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
        __be32 flow;
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
        hop_limit = ip6->hop_limit;

        /* Extract traffic class using bpf_skb_load_bytes for safe access */
        if (bpf_skb_load_bytes(skb, ETH_H_LEN, &flow, 4) < 0)
                return TC_ACT_OK;
        tos = (bpf_ntohl(flow) >> 20) & 0xFF;

        /* Save source IPv6 for checksum and extract IPv4 addresses */
        if (bpf_skb_load_bytes(skb, ETH_H_LEN + 8, src6_bytes, 16) < 0)
                return TC_ACT_OK;
        v6addr_to_v4(src6_bytes, cfg()->pref64_len, src4);
        __builtin_memcpy(dst4, cfg()->local_v4, 4);

        l4_off = ETH_H_LEN + IP6_H_LEN;

        /* Handle ICMPv6 translation */
        if (nexthdr == IPPROTO_ICMPV6) {
                /* Read original type+code as 16-bit value for checksum delta */
                __be16 old_tc;
                if (bpf_skb_load_bytes(skb, l4_off, &old_tc, 2) < 0)
                        return TC_ACT_OK;

                if (translate_icmp_6to4(skb, l4_off) < 0)
                        return TC_ACT_OK;

                /* Read new type+code after translation. The type was rewritten already, so do not
                 * let a half-translated packet pass on failure. */
                __be16 new_tc;
                if (bpf_skb_load_bytes(skb, l4_off, &new_tc, 2) < 0)
                        return TC_ACT_SHOT;

                /* Incrementally update the checksum for the type byte change.
                 * Do NOT zero the checksum — it contains the payload + pseudo-header state.
                 * Pseudo-header contribution will be removed after room adjustment. */
                if (bpf_l4_csum_replace(skb, l4_off + 2, old_tc, new_tc, 2) < 0)
                        return TC_ACT_SHOT;
        }

        /* Turn the skb into an IPv4 one. This shrinks the packet by 20 bytes and updates
         * skb->protocol, which TC programs cannot write directly. */
        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) < 0)
                return nexthdr == IPPROTO_ICMPV6 ? TC_ACT_SHOT : TC_ACT_OK;

        /* From here on the packet is modified: drop it rather than pass a broken one on. */
        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;

        if (!ensure_header(&eth, skb, &data, &data_end, 0))
                return TC_ACT_SHOT;
        eth->h_proto = bpf_htons(ETH_P_IP);

        /* Write IPv4 header */
        /* Assign the fields one by one instead of using an initializer: clang miscompiles the
         * initializer with bitfields for the BPF target, zeroing the first 8 bytes of the header
         * (version/ihl, tos, tot_len, id, frag_off) after they were stored. */
        struct iphdr ip4h;

        __builtin_memset(&ip4h, 0, sizeof(ip4h));
        ip4h.version = 4;
        ip4h.ihl = 5;
        ip4h.tos = tos;
        ip4h.tot_len = bpf_htons(IP_H_LEN + bpf_ntohs(payload_len));
        ip4h.frag_off = bpf_htons(IP_DF);
        ip4h.ttl = hop_limit;
        ip4h.protocol = (nexthdr == IPPROTO_ICMPV6) ? IPPROTO_ICMP : nexthdr;
        __builtin_memcpy(&ip4h.saddr, src4, 4);
        __builtin_memcpy(&ip4h.daddr, dst4, 4);

        /* Compute IPv4 header checksum with proper fold */
        __s64 hdr_csum = bpf_csum_diff(NULL, 0, (__be32 *)&ip4h, sizeof(ip4h), 0);
        __u32 sum = (__u32)(hdr_csum & 0xFFFFFFFF);
        sum = (sum & 0xFFFF) + (sum >> 16);
        sum = (sum & 0xFFFF) + (sum >> 16);
        ip4h.check = (__be16)~sum;

        if (bpf_skb_store_bytes(skb, ETH_H_LEN, &ip4h, sizeof(ip4h), 0) < 0)
                return TC_ACT_SHOT;

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
                if (bpf_l4_csum_replace(skb, coff, 0, delta, flags | BPF_F_PSEUDO_HDR) < 0)
                        return TC_ACT_SHOT;

        } else if (nexthdr == IPPROTO_ICMPV6) {
                /* Remove pseudo-header contribution from ICMPv6 → ICMP */
                struct { __u8 s[16]; __u8 d[16]; __be32 l; __u8 z[3]; __u8 n; } ph6;

                __builtin_memcpy(ph6.s, src6_bytes, 16);
                __builtin_memcpy(ph6.d, cfg()->local_v6, 16);
                ph6.l = bpf_htonl(bpf_ntohs(payload_len));
                __builtin_memset(ph6.z, 0, 3);
                ph6.n = IPPROTO_ICMPV6;

                __s64 neg_ph = bpf_csum_diff((__be32 *)&ph6, sizeof(ph6), NULL, 0, 0);
                if (bpf_l4_csum_replace(skb, l4_off + 2, 0, neg_ph, BPF_F_PSEUDO_HDR) < 0)
                        return TC_ACT_SHOT;
        }

        /* The packet is a complete IPv4 packet now (skb->protocol was updated by
         * bpf_skb_change_proto()), so just let it continue up the stack. */
        return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
