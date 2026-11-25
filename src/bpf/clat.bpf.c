/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* eBPF TC programs for CLAT (464XLAT, RFC 6877) IPv4↔IPv6 translation.
 *
 * Attached to an Ethernet interface's TC hooks:
 *   - Egress: translates outgoing IPv4 packets from 192.0.0.1 to IPv6 (CLAT → NAT64 gateway)
 *   - Ingress: translates incoming IPv6 packets to the CLAT address to IPv4 (NAT64 gateway → CLAT)
 *
 * Translation follows RFC 7915 (stateless IP/ICMP translation) with the address mapping of RFC 6052.
 *
 * The programs access the packet only through bpf_skb_load_bytes() and bpf_skb_store_bytes(), and avoid
 * variable offsets into the stack and the global data, so that CAP_BPF and CAP_NET_ADMIN are enough to
 * load them; CAP_PERFMON is not needed.
 *
 * Requires a kernel with TCX (6.6).
 *
 * Not translated: fragmented ICMP messages, whose checksum cannot be translated statelessly (RFC 7915 section
 * 1.2), and packets with IPv4 options, which are dropped. IPv6 packets with extension headers other than the
 * fragment header are left to the IPv6 stack. */

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
#define ICMP_H_LEN 8

/* Offsets of the checksum within the TCP and UDP headers. Constants, as offsetof() on the types of vmlinux.h
 * results in CO-RE relocations, which older clang versions miscompile in conditional expressions. */
#define TCP_CHECK_OFF 16
#define UDP_CHECK_OFF 6

/* IPv4 flags */
#define IP_DF      0x4000
#define IP_MF      0x2000
#define IP_OFFMASK 0x1FFF

#define NEXTHDR_FRAGMENT_HEADER 44
#define FRAGMENT_H_LEN 8

/* The IPv6 fragment header (RFC 8200 section 4.5) */
struct ipv6_fragment_header {
        __u8 nexthdr;
        __u8 reserved;
        __be16 frag_off;        /* offset in units of 8 bytes, and the M flag */
        __be32 id;
};

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

#define cfg() ((const struct clat_config *)&clat_cfg)

/* Counter of the IPv4 identification generator (RFC 7915 section 5.1, RFC 6864) */
struct ipv4_id_counter {
        struct bpf_spin_lock lock;
        __u32 next;
};

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct ipv4_id_counter);
} clat_ipv4_id SEC(".maps");

/* Number of IPv4 UDP datagrams without checksum that were dropped, reported by userspace */
__u64 clat_udp_zero_checksum_dropped = 0;

struct ipv6_pseudo_header {
        __u8 saddr[16];
        __u8 daddr[16];
        __be32 len;
        __u8 zero[3];
        __u8 nexthdr;
};

/* An ICMP error message up to the part of the quoted packet that the translation rewrites: the ICMP header,
 * the quoted IP header, the first 8 bytes of the quoted transport header, and the checksum (plus urgent
 * pointer) of a quoted TCP header, if present. */
struct icmp4_error {
        __u8 icmp[ICMP_H_LEN];
        __u8 ip[IP_H_LEN];
        __u8 l4[8];
        __u8 tcp[4];
};

struct icmp6_error {
        __u8 icmp[ICMP_H_LEN];
        __u8 ip[IP6_H_LEN];
        __u8 l4[8];
        __u8 tcp[4];
};

_Static_assert(sizeof(struct ipv6_pseudo_header) == 40, "unexpected padding");
_Static_assert(sizeof(struct icmp4_error) == 40, "unexpected padding");
_Static_assert(sizeof(struct icmp6_error) == 60, "unexpected padding");
_Static_assert(sizeof(struct iphdr) == IP_H_LEN, "unexpected size");
_Static_assert(sizeof(struct ipv6hdr) == IP6_H_LEN, "unexpected size");
_Static_assert(sizeof(struct ipv6_fragment_header) == FRAGMENT_H_LEN, "unexpected size");

/* The buffers needed to translate ICMP errors do not fit on the BPF stack. TC programs run with bottom halves
 * disabled, and the two directions use their own entry. */
struct icmp_scratch {
        struct icmp4_error v4;
        struct icmp6_error v6;
        struct ipv6_pseudo_header ph;
        struct ipv6hdr ip6;             /* outer headers */
        struct iphdr ip4;
        __u8 src6[16];
        __u8 dst6[16];
        __u8 quoted_addr6[16];
        __u8 src4[4];
        __u8 dst4[4];
        __u8 quoted_dst4[4];
        __be32 addrs4[2];               /* addresses of the quoted packet, for its checksum */
        __u8 addrs6[32];
        struct ipv6_fragment_header fragment;   /* of the quoted packet */
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 2);
        __type(key, __u32);
        __type(value, struct icmp_scratch);
} clat_scratch SEC(".maps");

#define SCRATCH_EGRESS  0
#define SCRATCH_INGRESS 1

static __always_inline struct icmp_scratch* icmp_scratch_get(__u32 key) {
        struct icmp_scratch *s = bpf_map_lookup_elem(&clat_scratch, &key);

        if (s)
                __builtin_memset(s, 0, sizeof(*s));

        return s;
}

/* Compare a 16 byte address with one in the global data */
static __always_inline bool addr_equal(const __u8 *a, const __u8 *b) {
        __u32 x[4], y[4];

        __builtin_memcpy(x, a, 16);
        __builtin_memcpy(y, b, 16);

        return ((x[0] ^ y[0]) | (x[1] ^ y[1]) | (x[2] ^ y[2]) | (x[3] ^ y[3])) == 0;
}

static __always_inline bool addr_in_pref64(const __u8 *a) {
        __u32 x[4], p[4], m[4];

        __builtin_memcpy(x, a, 16);
        __builtin_memcpy(p, cfg()->pref64, 16);
        __builtin_memcpy(m, cfg()->pref64_mask, 16);

        return (((x[0] ^ p[0]) & m[0]) | ((x[1] ^ p[1]) & m[1]) |
                ((x[2] ^ p[2]) & m[2]) | ((x[3] ^ p[3]) & m[3])) == 0;
}

/* Whether an IPv4 address may be translated into or from the NAT64 prefix */
static __always_inline bool ipv4_is_translatable(const __u8 *a) {
        if (cfg()->pref64_is_well_known)
                return clat_ipv4_is_global(a);

        return clat_ipv4_is_unicast(a);
}

/* The identification of the next translated IPv4 packet that may be fragmented */
static __noinline __u16 next_ipv4_id(void) {
        struct ipv4_id_counter *counter;
        __u32 key = 0, n;

        counter = bpf_map_lookup_elem(&clat_ipv4_id, &key);
        if (!counter)
                return 0;

        bpf_spin_lock(&counter->lock);
        n = counter->next++;
        bpf_spin_unlock(&counter->lock);

        return (__u16) (cfg()->ipv4_id_seed + n);
}

static __always_inline __u16 csum_fold(__u64 sum) {
        sum = (sum & 0xffffffff) + (sum >> 32);
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);
        sum = (sum & 0xffff) + (sum >> 16);

        return (__u16) ~sum;
}

/* Initialize an IPv4 header (without options) */
static __always_inline void ipv4_header_init(
                struct iphdr *ip4,
                __u8 tos,
                __u16 total_len,
                __u16 id,
                __u16 frag_off,
                __u8 ttl,
                __u8 protocol,
                const __u8 *saddr,
                const __u8 *daddr) {

        /* Assign the fields one by one instead of using an initializer: clang miscompiles the
         * initializer with bitfields for the BPF target, zeroing the first 8 bytes of the header
         * (version/ihl, tos, tot_len, id, frag_off) after they were stored. */
        __builtin_memset(ip4, 0, sizeof(*ip4));
        ip4->version = 4;
        ip4->ihl = 5;
        ip4->tos = tos;
        ip4->tot_len = bpf_htons(total_len);
        ip4->id = bpf_htons(id);
        ip4->frag_off = bpf_htons(frag_off);
        ip4->ttl = ttl;
        ip4->protocol = protocol;
        __builtin_memcpy(&ip4->saddr, saddr, 4);
        __builtin_memcpy(&ip4->daddr, daddr, 4);

        ip4->check = csum_fold(bpf_csum_diff(NULL, 0, (__be32 *) ip4, sizeof(*ip4), 0));
}

static __always_inline void ipv6_header_init(
                struct ipv6hdr *ip6,
                __u8 tclass,
                __u16 payload_len,
                __u8 nexthdr,
                __u8 hop_limit,
                const __u8 *saddr,
                const __u8 *daddr) {

        __be32 flow = bpf_htonl((__u32) 6 << 28 | (__u32) tclass << 20);

        __builtin_memcpy(ip6, &flow, 4);
        ip6->payload_len = bpf_htons(payload_len);
        ip6->nexthdr = nexthdr;
        ip6->hop_limit = hop_limit;
        __builtin_memcpy(&ip6->saddr, saddr, 16);
        __builtin_memcpy(&ip6->daddr, daddr, 16);
}

static __always_inline void pseudo_header_init(
                struct ipv6_pseudo_header *ph,
                const __u8 *saddr,
                const __u8 *daddr,
                __u32 len,
                __u8 nexthdr) {

        __builtin_memset(ph, 0, sizeof(struct ipv6_pseudo_header));
        __builtin_memcpy(ph->saddr, saddr, 16);
        __builtin_memcpy(ph->daddr, daddr, 16);
        ph->len = bpf_htonl(len);
        ph->nexthdr = nexthdr;
}

/* Update the checksum of an ICMP echo message whose type changes from 'old_type' to 'new_type' (RFC 1624),
 * and add the ICMPv6 pseudo-header to it, or remove it from it. */
static __always_inline __u16 icmp_echo_checksum(
                __u16 check,
                __u8 old_type,
                __u8 new_type,
                __u8 code,
                struct ipv6_pseudo_header *ph,
                bool add) {

        __u8 from[4] = { old_type, code }, to[4] = { new_type, code };
        __s64 sum;

        sum = bpf_csum_diff((__be32 *) from, sizeof(from), (__be32 *) to, sizeof(to), (__u16) ~check);
        sum = add ? bpf_csum_diff(NULL, 0, (__be32 *) ph, sizeof(struct ipv6_pseudo_header), sum) :
                    bpf_csum_diff((__be32 *) ph, sizeof(struct ipv6_pseudo_header), NULL, 0, sum);

        return csum_fold(sum);
}

/* Update the checksum of a TCP or UDP header in a packet quoted by an ICMP error. 'delta' is the difference
 * of the sums of the new and old addresses. */
static __always_inline void update_quoted_checksum(__u8 *field, __s64 delta, bool udp) {
        __u16 check;

        __builtin_memcpy(&check, field, 2);
        if (udp && check == 0)
                return;

        check = csum_fold((__u64) (__u16) ~check + (__u64) delta);
        if (udp && check == 0)
                check = 0xffff;

        __builtin_memcpy(field, &check, 2);
}

#define CSUM_CHUNK      512     /* the maximum size bpf_csum_diff() accepts */
#define CSUM_MAX_CHUNKS 18      /* 18 * 512 = 9216 bytes, enough for a UDP datagram in a 9000 byte MTU */

/* Buffer for payload_csum(), which is only used by the egress program */
struct csum_buffer {
        __u64 data[CSUM_CHUNK / 8];     /* aligned, so that clearing it can be inlined */
};

struct {
        __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, struct csum_buffer);
} clat_csum_buffer SEC(".maps");

struct payload_csum_state {
        struct __sk_buff *skb;
        __u32 off;
        __u32 len;      /* what is left to sum */
        __s64 sum;
};

/* Add the next chunk of the packet to the sum. Returns 1 to end the loop, on errors with len not zero. */
static long payload_csum_chunk(__u32 index, void *userdata) {
        struct payload_csum_state *state = userdata;
        struct csum_buffer *buf;
        __u32 key = 0;
        __s64 sum;
        /* 64 bit, so that the compiler does not zero-extend a copy for the checks below, which would leave
         * the verifier with no bounds on the register used as the size argument. */
        __u64 n, n4;

        if (state->len == 0)
                return 1;

        buf = bpf_map_lookup_elem(&clat_csum_buffer, &key);
        if (!buf)
                return 1;

        n = state->len < CSUM_CHUNK ? state->len : CSUM_CHUNK;
        /* Redundant, but the verifier needs to see the bounds on the size. The barrier keeps the compiler
         * from proving the check redundant and dropping it. */
        barrier_var(n);
        if (n == 0)
                return 1;
        barrier_var(n);         /* keep the two checks from being merged into one */
        if (n > CSUM_CHUNK)
                return 1;

        /* bpf_csum_diff() needs a multiple of 4 bytes: zero the padding. */
        __builtin_memset(buf->data, 0, sizeof(buf->data));
        if (bpf_skb_load_bytes(state->skb, state->off, buf->data, n) < 0)
                return 1;

        /* Round up to a multiple of 4. The verifier's range tracking is too coarse to see that this stays
         * within the buffer, so bound it explicitly. */
        n4 = (n + 3) & ~3ULL;
        barrier_var(n4);
        if (n4 == 0)
                return 1;
        barrier_var(n4);
        if (n4 > CSUM_CHUNK)
                return 1;

        sum = bpf_csum_diff(NULL, 0, (__be32 *) buf->data, n4, state->sum);
        if (sum < 0)
                return 1;

        state->sum = sum;
        state->off += n;
        state->len -= n;
        return 0;
}

/* Sum the 16-bit words of len bytes of the packet starting at off, as bpf_csum_diff() does (unfolded,
 * not inverted). The packet is read in chunks, with bpf_loop(), so that the verifier does not have to follow
 * each iteration. Returns a negative value if the data does not fit or cannot be read. */
static __noinline __s64 payload_csum(struct __sk_buff *skb, __u32 off, __u32 len) {
        struct payload_csum_state state = {
                .skb = skb,
                .off = off,
                .len = len,
        };

        if (bpf_loop(CSUM_MAX_CHUNKS, payload_csum_chunk, &state, 0) < 0)
                return -1;

        return state.len == 0 ? state.sum : -1;
}

static __always_inline int store_ethertype(struct __sk_buff *skb, __u16 ethertype) {
        __be16 proto = bpf_htons(ethertype);

        return bpf_skb_store_bytes(skb, ETH_H_LEN - 2, &proto, sizeof(proto), 0);
}

/* Translate an ICMPv4 error message sent by this host (RFC 7915 sections 4.2 and 4.3). The caller verified
 * the outer IPv4 header. */
static __noinline int icmp_error_4to6(struct __sk_buff *skb) {
        struct icmp_scratch *scratch;
        __u16 total_len, quoted_len, check;
        bool has_tcp_check = false;

        scratch = icmp_scratch_get(SCRATCH_EGRESS);
        if (!scratch)
                return TC_ACT_SHOT;

        struct icmp4_error *old = &scratch->v4;
        struct icmp6_error *new = &scratch->v6;
        struct iphdr *ip4 = &scratch->ip4, *quoted = (struct iphdr *) old->ip;
        struct ipv6hdr *ip6 = &scratch->ip6;
        __u8 *src6 = scratch->src6, *dst6 = scratch->dst6, *quoted_src6 = scratch->quoted_addr6;

        if (bpf_skb_load_bytes(skb, ETH_H_LEN, ip4, sizeof(*ip4)) < 0)
                return TC_ACT_SHOT;

        total_len = bpf_ntohs(ip4->tot_len);
        /* The translated message must not exceed the IPv6 minimum MTU (RFC 4443 section 2.4). The host
         * sends at most 576 bytes (RFC 1812 section 4.3.2.3), so this is not truncated here. */
        if (total_len < IP_H_LEN + ICMP_H_LEN + IP_H_LEN + 8 ||
            total_len > CLAT_IPV6_MIN_MTU - IP6_H_LEN)
                return TC_ACT_SHOT;

        if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP_H_LEN, old, ICMP_H_LEN + IP_H_LEN + 8) < 0)
                return TC_ACT_SHOT;

        if (quoted->version != 4 || quoted->ihl != 5 || (bpf_ntohs(quoted->frag_off) & IP_OFFMASK) != 0)
                return TC_ACT_SHOT;

        /* The quoted packet is one that was delivered to us */
        if (__builtin_memcmp(&quoted->daddr, cfg()->local_v4, 4) != 0 ||
            !ipv4_is_translatable((const __u8 *) &quoted->saddr))
                return TC_ACT_SHOT;

        quoted_len = bpf_ntohs(quoted->tot_len);
        if (quoted_len < IP_H_LEN)
                return TC_ACT_SHOT;

        if (clat_icmp_4to6(old->icmp, quoted_len, cfg()->mtu, new->icmp) != CLAT_ICMP_ERROR)
                return TC_ACT_SHOT;

        if (quoted->protocol == IPPROTO_TCP && total_len >= IP_H_LEN + ICMP_H_LEN + IP_H_LEN + 20) {
                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP_H_LEN + ICMP_H_LEN + IP_H_LEN + 16,
                                       old->tcp, sizeof(old->tcp)) < 0)
                        return TC_ACT_SHOT;
                has_tcp_check = true;
        }

        __builtin_memcpy(new->l4, old->l4, sizeof(new->l4));
        __builtin_memcpy(new->tcp, old->tcp, sizeof(new->tcp));

        __builtin_memcpy(src6, cfg()->local_v6, 16);
        clat_ipv4_embed(cfg()->pref64, cfg()->pref64_len, (const __u8 *) &ip4->daddr, dst6);
        clat_ipv4_embed(cfg()->pref64, cfg()->pref64_len, (const __u8 *) &quoted->saddr, quoted_src6);

        ipv6_header_init((struct ipv6hdr *) new->ip, quoted->tos, quoted_len - IP_H_LEN,
                         quoted->protocol == IPPROTO_ICMP ? IPPROTO_ICMPV6 : quoted->protocol,
                         quoted->ttl, quoted_src6, src6);

        /* The transport checksum of the quoted packet */
        if (quoted->protocol == IPPROTO_TCP || quoted->protocol == IPPROTO_UDP) {
                scratch->addrs4[0] = quoted->saddr;
                scratch->addrs4[1] = quoted->daddr;
                __builtin_memcpy(scratch->addrs6, quoted_src6, 16);
                __builtin_memcpy(scratch->addrs6 + 16, src6, 16);

                __s64 delta = bpf_csum_diff(scratch->addrs4, sizeof(scratch->addrs4),
                                            (__be32 *) scratch->addrs6, sizeof(scratch->addrs6), 0);
                if (delta < 0)
                        return TC_ACT_SHOT;

                /* Separate branches with constant offsets: the verifier does not allow a pointer selected
                 * at runtime. */
                if (quoted->protocol == IPPROTO_UDP)
                        update_quoted_checksum(new->l4 + 6, delta, /* udp= */ true);
                else if (has_tcp_check) {
                        barrier();
                        update_quoted_checksum(new->tcp, delta, /* udp= */ false);
                }

        } else if (quoted->protocol == IPPROTO_ICMP) {
                __u16 inner_check;

                if (old->l4[0] != 8 && old->l4[0] != 0)
                        return TC_ACT_SHOT;

                new->l4[0] = old->l4[0] == 8 ? 128 : 129;
                pseudo_header_init(&scratch->ph, quoted_src6, src6, quoted_len - IP_H_LEN, IPPROTO_ICMPV6);

                __builtin_memcpy(&inner_check, old->l4 + 2, 2);
                inner_check = icmp_echo_checksum(inner_check, old->l4[0], new->l4[0], old->l4[1],
                                                 &scratch->ph, /* add= */ true);
                __builtin_memcpy(new->l4 + 2, &inner_check, 2);
        } else
                return TC_ACT_SHOT;

        /* The checksum of the message itself: replace the rewritten headers, and add the pseudo-header */
        __builtin_memcpy(&check, old->icmp + 2, 2);
        old->icmp[2] = old->icmp[3] = 0;
        pseudo_header_init(&scratch->ph, src6, dst6, total_len, IPPROTO_ICMPV6);

        __s64 sum = bpf_csum_diff((__be32 *) old, sizeof(*old), (__be32 *) new, sizeof(*new), (__u16) ~check);
        if (sum < 0)
                return TC_ACT_SHOT;
        sum = bpf_csum_diff(NULL, 0, (__be32 *) &scratch->ph, sizeof(scratch->ph), sum);
        if (sum < 0)
                return TC_ACT_SHOT;
        check = csum_fold(sum);
        __builtin_memcpy(new->icmp + 2, &check, 2);

        ipv6_header_init(ip6, ip4->tos, total_len, IPPROTO_ICMPV6, ip4->ttl, src6, dst6);

        /* Replace the outer header, then make room for the longer quoted header */
        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0 ||
            bpf_skb_adjust_room(skb, IP6_H_LEN - IP_H_LEN, BPF_ADJ_ROOM_NET, 0) < 0 ||
            store_ethertype(skb, ETH_P_IPV6) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN, ip6, sizeof(*ip6), BPF_F_RECOMPUTE_CSUM) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN + IP6_H_LEN, new, ICMP_H_LEN + IP6_H_LEN + 8,
                                BPF_F_RECOMPUTE_CSUM) < 0)
                return TC_ACT_SHOT;

        if (has_tcp_check &&
            bpf_skb_store_bytes(skb, ETH_H_LEN + IP6_H_LEN + ICMP_H_LEN + IP6_H_LEN + 16,
                                new->tcp, sizeof(new->tcp), BPF_F_RECOMPUTE_CSUM) < 0)
                return TC_ACT_SHOT;

        return bpf_redirect_neigh(skb->ifindex, NULL, 0, 0);
}

/* Translate an ICMPv6 error message about a packet we sent (RFC 7915 sections 5.2 and 5.3). The caller
 * verified that it is addressed to the CLAT address. Messages about other packets, i.e. about packets that
 * were not translated, are passed to the IPv6 stack. */
static __noinline int icmp_error_6to4(struct __sk_buff *skb) {
        struct icmp_scratch *scratch;
        __u16 payload_len, quoted_payload_len, total_len, check, quoted_frag_off = 0, quoted_id = 0;
        __u8 protocol, quoted_nexthdr, flow[2];
        __u32 extra = 0;                /* length of the fragment header of the quoted packet */
        bool has_tcp_check = false, quoted_first = true;

        scratch = icmp_scratch_get(SCRATCH_INGRESS);
        if (!scratch)
                return TC_ACT_OK;

        struct icmp6_error *old = &scratch->v6;
        struct icmp4_error *new = &scratch->v4;
        struct ipv6hdr *ip6 = &scratch->ip6, *quoted = (struct ipv6hdr *) old->ip;
        struct iphdr *ip4 = &scratch->ip4;
        __u8 *src4 = scratch->src4, *dst4 = scratch->dst4, *quoted_dst4 = scratch->quoted_dst4;

        if (bpf_skb_load_bytes(skb, ETH_H_LEN, ip6, sizeof(*ip6)) < 0)
                return TC_ACT_OK;

        payload_len = bpf_ntohs(ip6->payload_len);
        if (payload_len < ICMP_H_LEN + IP6_H_LEN + 8)
                return TC_ACT_OK;

        if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN, old, ICMP_H_LEN + IP6_H_LEN + 8) < 0)
                return TC_ACT_OK;

        if (!addr_equal((const __u8 *) &quoted->saddr, cfg()->local_v6) ||
            !addr_in_pref64((const __u8 *) &quoted->daddr))
                return TC_ACT_OK;

        quoted_payload_len = bpf_ntohs(quoted->payload_len);
        if (quoted_payload_len > 0xffff - IP_H_LEN)
                return TC_ACT_SHOT;

        quoted_nexthdr = quoted->nexthdr;
        if (quoted_nexthdr == NEXTHDR_FRAGMENT_HEADER) {
                struct ipv6_fragment_header *fragment = &scratch->fragment;

                if (payload_len < ICMP_H_LEN + IP6_H_LEN + FRAGMENT_H_LEN + 8 ||
                    quoted_payload_len < FRAGMENT_H_LEN)
                        return TC_ACT_SHOT;

                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN + ICMP_H_LEN + IP6_H_LEN,
                                       fragment, sizeof(*fragment)) < 0 ||
                    bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN + ICMP_H_LEN + IP6_H_LEN + FRAGMENT_H_LEN,
                                       old->l4, sizeof(old->l4)) < 0)
                        return TC_ACT_SHOT;

                quoted_nexthdr = fragment->nexthdr;
                if (quoted_nexthdr != IPPROTO_TCP && quoted_nexthdr != IPPROTO_UDP)
                        return TC_ACT_SHOT;

                quoted_first = (bpf_ntohs(fragment->frag_off) >> 3) == 0;
                quoted_frag_off = (bpf_ntohs(fragment->frag_off) >> 3) |
                        ((bpf_ntohs(fragment->frag_off) & 1) ? IP_MF : 0);
                quoted_id = (__u16) bpf_ntohl(fragment->id);
                quoted_payload_len -= FRAGMENT_H_LEN;
                extra = FRAGMENT_H_LEN;
        }

        switch (quoted_nexthdr) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
                protocol = quoted_nexthdr;
                break;
        case IPPROTO_ICMPV6:
                protocol = IPPROTO_ICMP;
                break;
        default:
                return TC_ACT_SHOT;
        }

        if (clat_icmp_6to4(old->icmp, cfg()->mtu, new->icmp) != CLAT_ICMP_ERROR)
                return TC_ACT_SHOT;

        /* The source is typically the NAT64 gateway, in which case it is mapped back, but may be any router
         * on the way (RFC 6791) */
        if (addr_in_pref64((const __u8 *) &ip6->saddr)) {
                clat_ipv4_extract((const __u8 *) &ip6->saddr, cfg()->pref64_len, src4);
                if (!ipv4_is_translatable(src4))
                        return TC_ACT_SHOT;
        } else
                clat_ipv4_dummy_address(src4);

        __builtin_memcpy(dst4, cfg()->local_v4, 4);
        clat_ipv4_extract((const __u8 *) &quoted->daddr, cfg()->pref64_len, quoted_dst4);

        if (protocol == IPPROTO_TCP && quoted_first && payload_len >= ICMP_H_LEN + IP6_H_LEN + extra + 20) {
                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN + ICMP_H_LEN + IP6_H_LEN + extra + 16,
                                       old->tcp, sizeof(old->tcp)) < 0)
                        return TC_ACT_SHOT;
                has_tcp_check = true;
        }

        __builtin_memcpy(new->l4, old->l4, sizeof(new->l4));
        __builtin_memcpy(new->tcp, old->tcp, sizeof(new->tcp));

        __builtin_memcpy(flow, old->ip, 2);
        total_len = quoted_payload_len + IP_H_LEN;
        ipv4_header_init((struct iphdr *) new->ip, (flow[0] << 4) | (flow[1] >> 4), total_len, quoted_id,
                         extra > 0 ? quoted_frag_off : total_len <= CLAT_IPV4_MAX_SIZE_WITHOUT_DF ? 0 : IP_DF,
                         quoted->hop_limit, protocol, dst4, quoted_dst4);

        /* The transport checksum of the quoted packet, which only the first fragment has */
        if (!quoted_first) {
                /* Nothing to update */
        } else if (protocol == IPPROTO_TCP || protocol == IPPROTO_UDP) {
                __builtin_memcpy(scratch->addrs6, &quoted->saddr, 16);
                __builtin_memcpy(scratch->addrs6 + 16, &quoted->daddr, 16);
                __builtin_memcpy(&scratch->addrs4[0], dst4, 4);
                __builtin_memcpy(&scratch->addrs4[1], quoted_dst4, 4);

                __s64 delta = bpf_csum_diff((__be32 *) scratch->addrs6, sizeof(scratch->addrs6),
                                            scratch->addrs4, sizeof(scratch->addrs4), 0);
                if (delta < 0)
                        return TC_ACT_SHOT;

                if (protocol == IPPROTO_UDP)
                        update_quoted_checksum(new->l4 + 6, delta, /* udp= */ true);
                else if (has_tcp_check) {
                        barrier();
                        update_quoted_checksum(new->tcp, delta, /* udp= */ false);
                }
        } else {
                __u16 inner_check;

                if (old->l4[0] != 128 && old->l4[0] != 129)
                        return TC_ACT_SHOT;

                new->l4[0] = old->l4[0] == 128 ? 8 : 0;
                pseudo_header_init(&scratch->ph, (const __u8 *) &quoted->saddr, (const __u8 *) &quoted->daddr,
                                   quoted_payload_len, IPPROTO_ICMPV6);

                __builtin_memcpy(&inner_check, old->l4 + 2, 2);
                inner_check = icmp_echo_checksum(inner_check, old->l4[0], new->l4[0], old->l4[1],
                                                 &scratch->ph, /* add= */ false);
                __builtin_memcpy(new->l4 + 2, &inner_check, 2);
        }

        /* The checksum of the message itself: replace the rewritten headers, and remove the pseudo-header */
        __builtin_memcpy(&check, old->icmp + 2, 2);
        old->icmp[2] = old->icmp[3] = 0;
        pseudo_header_init(&scratch->ph, (const __u8 *) &ip6->saddr, (const __u8 *) &ip6->daddr,
                           payload_len, IPPROTO_ICMPV6);

        __s64 sum = bpf_csum_diff((__be32 *) old, sizeof(*old), (__be32 *) new, sizeof(*new), (__u16) ~check);
        if (sum < 0)
                return TC_ACT_SHOT;
        sum = bpf_csum_diff((__be32 *) &scratch->ph, sizeof(scratch->ph), NULL, 0, sum);
        if (sum < 0)
                return TC_ACT_SHOT;
        if (extra > 0) {
                /* The fragment header of the quoted packet is removed */
                sum = bpf_csum_diff((__be32 *) &scratch->fragment, sizeof(scratch->fragment), NULL, 0, sum);
                if (sum < 0)
                        return TC_ACT_SHOT;
        }
        check = csum_fold(sum);
        __builtin_memcpy(new->icmp + 2, &check, 2);

        /* Both headers shrink by 20 bytes, so the total length is the payload length of the IPv6 packet,
         * without the fragment header of the quoted packet */
        total_len = payload_len - extra;
        __builtin_memcpy(flow, ip6, 2);
        ipv4_header_init(ip4, (flow[0] << 4) | (flow[1] >> 4), total_len,
                         total_len <= CLAT_IPV4_MAX_SIZE_WITHOUT_DF ? next_ipv4_id() : 0,
                         total_len <= CLAT_IPV4_MAX_SIZE_WITHOUT_DF ? 0 : IP_DF,
                         ip6->hop_limit, IPPROTO_ICMP, src4, dst4);

        /* Replace the outer header, then remove the room the shorter quoted header does not need */
        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) < 0 ||
            bpf_skb_adjust_room(skb, IP_H_LEN - IP6_H_LEN - (__s32) extra, BPF_ADJ_ROOM_NET, 0) < 0 ||
            store_ethertype(skb, ETH_P_IP) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN, ip4, sizeof(*ip4), BPF_F_RECOMPUTE_CSUM) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN + IP_H_LEN, new, ICMP_H_LEN + IP_H_LEN + 8,
                                BPF_F_RECOMPUTE_CSUM) < 0)
                return TC_ACT_SHOT;

        if (has_tcp_check &&
            bpf_skb_store_bytes(skb, ETH_H_LEN + IP_H_LEN + ICMP_H_LEN + IP_H_LEN + 16,
                                new->tcp, sizeof(new->tcp), BPF_F_RECOMPUTE_CSUM) < 0)
                return TC_ACT_SHOT;

        return TC_ACT_OK;
}

/* Egress: IPv4 → IPv6 translation */
SEC("tcx/egress")
int clat_egress(struct __sk_buff *skb) {
        struct ethhdr eth;
        struct iphdr ip4;
        __u8 src6[16], dst6[16], icmp[4] = {}, icmp6[4] = {};
        __u16 total_len, payload_len, frag_off;
        __u8 protocol;
        bool fragment, first;
        __u32 extra;

        if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
                return TC_ACT_OK;
        if (eth.h_proto != bpf_htons(ETH_P_IP))
                return TC_ACT_OK;
        if (bpf_skb_load_bytes(skb, ETH_H_LEN, &ip4, sizeof(ip4)) < 0)
                return TC_ACT_OK;

        /* Only translate packets from our CLAT IPv4 address */
        if (__builtin_memcmp(&ip4.saddr, cfg()->local_v4, 4) != 0) {
                /* Other packets must not be sent to the placeholder address of the IPv4 gateway either,
                 * switches would flood them to every port. */
                if (__builtin_memcmp(eth.h_dest, cfg()->gateway_mac, 6) == 0)
                        return TC_ACT_SHOT;

                return TC_ACT_OK;
        }

        /* From here on the packet is from our CLAT address. If it cannot be translated, drop it: passing it
         * on would send IPv4 to the placeholder neighbour of the gateway. */

        /* Only handle standard 20-byte IPv4 headers (no options) */
        if (ip4.version != 4 || ip4.ihl != 5)
                return TC_ACT_SHOT;

        frag_off = bpf_ntohs(ip4.frag_off);
        fragment = (frag_off & (IP_MF | IP_OFFMASK)) != 0;
        first = (frag_off & IP_OFFMASK) == 0;
        extra = fragment ? FRAGMENT_H_LEN : 0;

        /* Multicast, broadcast, and with the Well-Known Prefix private addresses cannot be translated */
        if (!ipv4_is_translatable((const __u8 *) &ip4.daddr))
                return TC_ACT_SHOT;

        total_len = bpf_ntohs(ip4.tot_len);
        if (total_len < IP_H_LEN)
                return TC_ACT_SHOT;
        payload_len = total_len - IP_H_LEN;

        protocol = ip4.protocol;
        if (fragment) {
                /* Fragmented ICMP messages cannot be translated (RFC 7915 section 1.2). The first fragment
                 * has to hold the transport header with the checksum. */
                if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
                        return TC_ACT_SHOT;
                if (first && payload_len < (protocol == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)))
                        return TC_ACT_SHOT;
        }

        if (protocol == IPPROTO_ICMP) {
                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP_H_LEN, icmp, sizeof(icmp)) < 0)
                        return TC_ACT_SHOT;

                if (icmp[0] != 8 && icmp[0] != 0) /* not an echo request or reply */
                        return icmp_error_4to6(skb);

        } else if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP)
                return TC_ACT_SHOT;

        __builtin_memcpy(src6, cfg()->local_v6, 16);
        clat_ipv4_embed(cfg()->pref64, cfg()->pref64_len, (const __u8 *) &ip4.daddr, dst6);

        /* IPv6 does not allow a zero UDP checksum (RFC 8200 section 8.1), while IPv4 does ("not
         * computed"). Depending on the configuration, drop such a datagram, or compute the checksum
         * (RFC 7915 section 4.5). There is nothing to update incrementally then: sum up the datagram now,
         * while the packet is still untouched. */
        bool udp_zero_csum = false;
        __s64 udp_sum = 0;

        if (protocol == IPPROTO_UDP && first) {
                struct udphdr udp;

                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP_H_LEN, &udp, sizeof(udp)) < 0)
                        return TC_ACT_SHOT;

                if (udp.check == 0) {
                        /* The checksum of a fragmented datagram cannot be computed */
                        if (cfg()->drop_udp_zero_checksum || fragment || bpf_ntohs(udp.len) != payload_len) {
                                __sync_fetch_and_add(&clat_udp_zero_checksum_dropped, 1);
                                return TC_ACT_SHOT;
                        }

                        udp_zero_csum = true;
                        udp_sum = payload_csum(skb, ETH_H_LEN + IP_H_LEN, payload_len);
                        if (udp_sum < 0) {
                                __sync_fetch_and_add(&clat_udp_zero_checksum_dropped, 1);
                                return TC_ACT_SHOT;
                        }
                }

        } else if (protocol == IPPROTO_ICMP) {
                /* Update the checksum incrementally for the new type, and add the pseudo-header, which
                 * ICMPv4 does not have */
                struct ipv6_pseudo_header ph;
                __u16 check;

                __builtin_memcpy(&check, icmp + 2, 2);
                icmp6[0] = icmp[0] == 8 ? 128 : 129;
                icmp6[1] = icmp[1];

                pseudo_header_init(&ph, src6, dst6, payload_len, IPPROTO_ICMPV6);
                check = icmp_echo_checksum(check, icmp[0], icmp6[0], icmp[1], &ph, /* add= */ true);
                __builtin_memcpy(icmp6 + 2, &check, 2);
        }

        struct ipv6hdr ip6;
        ipv6_header_init(&ip6, ip4.tos, payload_len + extra,
                         fragment ? NEXTHDR_FRAGMENT_HEADER :
                         protocol == IPPROTO_ICMP ? IPPROTO_ICMPV6 : protocol,
                         ip4.ttl, src6, dst6);

        /* RFC 7915 section 4.1 */
        struct ipv6_fragment_header fragment_header = {
                .nexthdr = protocol,
                .frag_off = bpf_htons((__u16) ((frag_off & IP_OFFMASK) << 3) | ((frag_off & IP_MF) ? 1 : 0)),
                .id = bpf_htonl(bpf_ntohs(ip4.id)),
        };

        /* Turn the skb into an IPv6 one. This grows the packet by 20 bytes for the IPv6 header
         * and updates skb->protocol, which TC programs cannot write directly. The new headers
         * are filled in below. */
        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IPV6), 0) < 0)
                return TC_ACT_SHOT;

        /* From here on the packet is modified: drop it rather than pass a broken one on. */
        if (fragment &&
            (bpf_skb_adjust_room(skb, FRAGMENT_H_LEN, BPF_ADJ_ROOM_NET, 0) < 0 ||
             bpf_skb_store_bytes(skb, ETH_H_LEN + IP6_H_LEN, &fragment_header, sizeof(fragment_header),
                                 BPF_F_RECOMPUTE_CSUM) < 0))
                return TC_ACT_SHOT;

        if (store_ethertype(skb, ETH_P_IPV6) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN, &ip6, sizeof(ip6), BPF_F_RECOMPUTE_CSUM) < 0)
                return TC_ACT_SHOT;

        if (!first) {
                /* No transport header, hence no checksum to update */
        } else if (protocol == IPPROTO_ICMP) {
                if (bpf_skb_store_bytes(skb, ETH_H_LEN + IP6_H_LEN, icmp6, sizeof(icmp6), BPF_F_RECOMPUTE_CSUM) < 0)
                        return TC_ACT_SHOT;

        } else if (udp_zero_csum) {
                /* Finish the sum over the datagram with the IPv6 pseudo-header */
                struct ipv6_pseudo_header ph;
                __u16 check;

                pseudo_header_init(&ph, src6, dst6, payload_len, IPPROTO_UDP);
                __s64 sum = bpf_csum_diff(NULL, 0, (__be32 *) &ph, sizeof(ph), udp_sum);
                if (sum < 0)
                        return TC_ACT_SHOT;

                /* A computed zero is sent as 0xFFFF (RFC 768) */
                check = csum_fold(sum);
                if (check == 0)
                        check = 0xffff;

                if (bpf_skb_store_bytes(skb, ETH_H_LEN + IP6_H_LEN + UDP_CHECK_OFF,
                                        &check, sizeof(check), 0) < 0)
                        return TC_ACT_SHOT;
        } else {
                /* Only the addresses differ between the IPv4 and IPv6 pseudo-headers; the length and the
                 * protocol contribute the same. */
                struct { __be32 s; __be32 d; } addrs4 = { ip4.saddr, ip4.daddr };
                struct { __u8 s[16]; __u8 d[16]; } addrs6;

                __builtin_memcpy(addrs6.s, src6, 16);
                __builtin_memcpy(addrs6.d, dst6, 16);

                __s64 delta = bpf_csum_diff((__be32 *) &addrs4, sizeof(addrs4),
                                            (__be32 *) &addrs6, sizeof(addrs6), 0);
                if (delta < 0)
                        return TC_ACT_SHOT;

                __u32 off = ETH_H_LEN + IP6_H_LEN + extra +
                        (protocol == IPPROTO_TCP ? TCP_CHECK_OFF : UDP_CHECK_OFF);
                __u64 flags = BPF_F_PSEUDO_HDR | (protocol == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);

                if (bpf_l4_csum_replace(skb, off, 0, delta, flags) < 0)
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
        struct ethhdr eth;
        struct ipv6hdr ip6;
        struct iphdr ip4;
        __u8 src4[4], dst4[4], flow[2], icmp6[4] = {}, icmp[4] = {};
        __u16 payload_len, total_len, frag_off = 0, id = 0;
        __u8 nexthdr;
        bool fragment = false, first = true;
        __u32 extra = 0;

        if (bpf_skb_load_bytes(skb, 0, &eth, sizeof(eth)) < 0)
                return TC_ACT_OK;

        if (eth.h_proto == bpf_htons(ETH_P_IP)) {
                /* 192.0.0.1 sits on the physical interface, so any on-link host could send native IPv4
                 * to it from any source, skipping the checks below. Only translated packets are
                 * legitimate, and those never pass through here as IPv4. */
                if (bpf_skb_load_bytes(skb, ETH_H_LEN, &ip4, sizeof(ip4)) >= 0 &&
                    __builtin_memcmp(&ip4.daddr, cfg()->local_v4, 4) == 0)
                        return TC_ACT_SHOT;

                return TC_ACT_OK;
        }
        if (eth.h_proto != bpf_htons(ETH_P_IPV6))
                return TC_ACT_OK;
        if (bpf_skb_load_bytes(skb, ETH_H_LEN, &ip6, sizeof(ip6)) < 0)
                return TC_ACT_OK;

        /* Only translate packets to our CLAT IPv6 address */
        if (!addr_equal((const __u8 *) &ip6.daddr, cfg()->local_v6))
                return TC_ACT_OK;

        nexthdr = ip6.nexthdr;
        if (nexthdr == IPPROTO_ICMPV6) {
                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN, icmp6, sizeof(icmp6)) < 0)
                        return TC_ACT_OK;

                if (icmp6[0] < 128) /* error messages, which may come from any router */
                        return icmp_error_6to4(skb);

                if (icmp6[0] != 128 && icmp6[0] != 129) /* e.g. neighbor discovery */
                        return TC_ACT_OK;

        } else if (nexthdr == NEXTHDR_FRAGMENT_HEADER) {
                struct ipv6_fragment_header fragment_header;

                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN, &fragment_header, sizeof(fragment_header)) < 0)
                        return TC_ACT_OK;

                /* Fragmented ICMPv6 messages cannot be translated (RFC 7915 section 1.2) */
                nexthdr = fragment_header.nexthdr;
                if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
                        return TC_ACT_OK;

                /* RFC 7915 section 5.1.1 */
                fragment = true;
                extra = FRAGMENT_H_LEN;
                first = (bpf_ntohs(fragment_header.frag_off) >> 3) == 0;
                frag_off = (bpf_ntohs(fragment_header.frag_off) >> 3) |
                        ((bpf_ntohs(fragment_header.frag_off) & 1) ? IP_MF : 0);
                id = (__u16) bpf_ntohl(fragment_header.id);

        } else if (nexthdr != IPPROTO_TCP && nexthdr != IPPROTO_UDP)
                return TC_ACT_OK;

        /* Only translate packets from the NAT64 prefix */
        if (!addr_in_pref64((const __u8 *) &ip6.saddr))
                return TC_ACT_OK;

        clat_ipv4_extract((const __u8 *) &ip6.saddr, cfg()->pref64_len, src4);
        __builtin_memcpy(dst4, cfg()->local_v4, 4);

        /* RFC 6052 section 3.1: spoofed sources would show up as private IPv4 hosts */
        if (!ipv4_is_translatable(src4))
                return TC_ACT_SHOT;

        payload_len = bpf_ntohs(ip6.payload_len);
        if (payload_len == 0 || payload_len < extra || payload_len > 0xffff - IP_H_LEN ||
            skb->len < (__u32) ETH_H_LEN + IP6_H_LEN + payload_len)
                return TC_ACT_SHOT;
        total_len = payload_len - extra + IP_H_LEN;

        /* The first fragment has to hold the transport header with the checksum */
        if (fragment && first &&
            payload_len - extra < (nexthdr == IPPROTO_TCP ? sizeof(struct tcphdr) : sizeof(struct udphdr)))
                return TC_ACT_SHOT;

        if (nexthdr == IPPROTO_UDP && first) {
                struct udphdr udp;

                /* A zero UDP checksum is not valid in IPv6. After the translation it would be an IPv4
                 * datagram without checksum, accepted unverified, so drop it. */
                if (bpf_skb_load_bytes(skb, ETH_H_LEN + IP6_H_LEN + extra, &udp, sizeof(udp)) < 0 || udp.check == 0)
                        return TC_ACT_SHOT;

        } else if (nexthdr == IPPROTO_ICMPV6) {
                /* Update the checksum incrementally for the new type, and remove the pseudo-header */
                struct ipv6_pseudo_header ph;
                __u16 check;

                __builtin_memcpy(&check, icmp6 + 2, 2);
                icmp[0] = icmp6[0] == 128 ? 8 : 0;
                icmp[1] = icmp6[1];

                pseudo_header_init(&ph, (const __u8 *) &ip6.saddr, (const __u8 *) &ip6.daddr,
                                   payload_len, IPPROTO_ICMPV6);
                check = icmp_echo_checksum(check, icmp6[0], icmp[0], icmp6[1], &ph, /* add= */ false);
                __builtin_memcpy(icmp + 2, &check, 2);
        }

        /* RFC 7915 section 5.1: DF must be clear for packets of up to 1260 bytes, they can be fragmented
         * by an IPv4 hop with a smaller MTU, as the sender could not have known. Those need an
         * identification (RFC 6864 section 4.3). */
        __builtin_memcpy(flow, &ip6, 2);
        if (!fragment) {
                if (total_len <= CLAT_IPV4_MAX_SIZE_WITHOUT_DF)
                        id = next_ipv4_id();
                else
                        frag_off = IP_DF;
        }
        ipv4_header_init(&ip4, (flow[0] << 4) | (flow[1] >> 4), total_len, id, frag_off,
                         ip6.hop_limit,
                         nexthdr == IPPROTO_ICMPV6 ? IPPROTO_ICMP : nexthdr,
                         src4, dst4);

        /* Turn the skb into an IPv4 one. This shrinks the packet by 20 bytes and updates
         * skb->protocol, which TC programs cannot write directly. */
        if (bpf_skb_change_proto(skb, bpf_htons(ETH_P_IP), 0) < 0)
                return TC_ACT_SHOT;

        /* From here on the packet is modified: drop it rather than pass a broken one on. */
        if (fragment && bpf_skb_adjust_room(skb, -FRAGMENT_H_LEN, BPF_ADJ_ROOM_NET, 0) < 0)
                return TC_ACT_SHOT;

        if (store_ethertype(skb, ETH_P_IP) < 0 ||
            bpf_skb_store_bytes(skb, ETH_H_LEN, &ip4, sizeof(ip4), BPF_F_RECOMPUTE_CSUM) < 0)
                return TC_ACT_SHOT;

        if (!first) {
                /* No transport header, hence no checksum to update */
        } else if (nexthdr == IPPROTO_ICMPV6) {
                if (bpf_skb_store_bytes(skb, ETH_H_LEN + IP_H_LEN, icmp, sizeof(icmp), BPF_F_RECOMPUTE_CSUM) < 0)
                        return TC_ACT_SHOT;
        } else {
                struct { __u8 s[16]; __u8 d[16]; } addrs6;
                struct { __u8 s[4]; __u8 d[4]; } addrs4;

                __builtin_memcpy(addrs6.s, &ip6.saddr, 16);
                __builtin_memcpy(addrs6.d, &ip6.daddr, 16);
                __builtin_memcpy(addrs4.s, src4, 4);
                __builtin_memcpy(addrs4.d, dst4, 4);

                __s64 delta = bpf_csum_diff((__be32 *) &addrs6, sizeof(addrs6),
                                            (__be32 *) &addrs4, sizeof(addrs4), 0);
                if (delta < 0)
                        return TC_ACT_SHOT;

                __u32 off = ETH_H_LEN + IP_H_LEN +
                        (nexthdr == IPPROTO_TCP ? TCP_CHECK_OFF : UDP_CHECK_OFF);
                __u64 flags = BPF_F_PSEUDO_HDR | (nexthdr == IPPROTO_UDP ? BPF_F_MARK_MANGLED_0 : 0);

                if (bpf_l4_csum_replace(skb, off, 0, delta, flags) < 0)
                        return TC_ACT_SHOT;
        }

        /* The packet is a complete IPv4 packet now (skb->protocol was updated by
         * bpf_skb_change_proto()), so just let it continue up the stack. */
        return TC_ACT_OK;
}

/* The checksum and redirect helpers used above are available to GPL compatible programs only */
char _license[] SEC("license") = "GPL";
