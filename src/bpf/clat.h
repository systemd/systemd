/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* Definitions shared between the CLAT (RFC 6877) BPF program and systemd-networkd, which translates in
 * userspace where the BPF program cannot be used. The address mapping (RFC 6052) and the ICMP type, code,
 * MTU and pointer translation (RFC 7915) live here, so that both translators behave the same.
 *
 * Only plain C types are used, to avoid header conflicts between the BPF context (vmlinux.h) and the
 * userspace context (netinet/in.h). */

#define CLAT_INLINE static inline __attribute__((__always_inline__))

/* RFC 7915 section 5.1: translated IPv4 packets up to this size must not have DF set */
#define CLAT_IPV4_MAX_SIZE_WITHOUT_DF 1260U
/* RFC 8200 section 5 */
#define CLAT_IPV6_MIN_MTU 1280U
/* The translation adds 20 bytes, and fragments gain a fragment header of 8 more bytes. IPv4 packets this much
 * smaller than the IPv6 MTU always fit. */
#define CLAT_MTU_OVERHEAD 28U

/* Configuration of the BPF program, which userspace fills in through the skeleton's BSS data before the
 * program is attached.
 *
 * The variable in the BPF program is declared with an anonymous struct built from these fields, so that
 * the generated skeleton carries the full definition and does not depend on this header. The named
 * struct is only used by the BPF program to get a non-volatile view of the variable. */
#define CLAT_CONFIG_FIELDS                                                                              \
        unsigned char local_v6[16];             /* CLAT IPv6 address */                                 \
        unsigned char pref64[16];               /* NAT64 prefix */                                      \
        unsigned char pref64_mask[16];          /* netmask of the NAT64 prefix */                       \
        unsigned char local_v4[4];              /* CLAT IPv4 address, 192.0.0.1 */                      \
        unsigned char gateway_mac[6];           /* link layer address of the IPv4 gateway */            \
        unsigned char drop_udp_zero_checksum;   /* drop IPv4 UDP datagrams without checksum */          \
        unsigned char pref64_is_well_known;     /* the prefix is 64:ff9b::/96 */                        \
        unsigned int pref64_len;                /* 32, 40, 48, 56, 64 or 96 */                          \
        unsigned int mtu;                       /* MTU of the link */                                   \
        unsigned int ipv4_id_seed;              /* start of the IPv4 identification generator */

struct clat_config {
        CLAT_CONFIG_FIELDS
};

/* RFC 7335: the CLAT IPv4 address, and the next hop of the IPv4 default route */
#define CLAT_IPV4_ADDRESS 0xc0000001U           /* 192.0.0.1 */
#define CLAT_IPV4_GATEWAY 0xc0000002U           /* 192.0.0.2 */

/* RFC 7600 section 4.8: the IPv4 dummy address, used as the source of translated ICMPv6 errors whose
 * source is not within the NAT64 prefix, e.g. from an IPv6 router in front of the NAT64 (RFC 6791) */
CLAT_INLINE void clat_ipv4_dummy_address(unsigned char *ret) {
        ret[0] = 192;
        ret[1] = 0;
        ret[2] = 0;
        ret[3] = 8;
}

/* Addresses that cannot be the source or destination of a packet we translate */
CLAT_INLINE int clat_ipv4_is_unicast(const unsigned char *a) {
        /* "This network", loopback, multicast, reserved and broadcast */
        return a[0] != 0 && a[0] != 127 && a[0] < 224;
}

/* RFC 6052 section 3.1: the Well-Known Prefix must not be used to represent non-global IPv4 addresses,
 * such as those of RFC 1918 or listed in section 3 of RFC 5735, plus the shared address space of RFC 6598.
 * 192.88.99.0/24 (6to4 relay anycast) is globally reachable according to RFC 6890. */
CLAT_INLINE int clat_ipv4_is_global(const unsigned char *a) {
        if (!clat_ipv4_is_unicast(a) || a[0] == 10)
                return 0;
        if (a[0] == 100 && (a[1] & 0xc0) == 64)                                 /* 100.64.0.0/10 */
                return 0;
        if (a[0] == 169 && a[1] == 254)                                         /* 169.254.0.0/16 */
                return 0;
        if (a[0] == 172 && (a[1] & 0xf0) == 16)                                 /* 172.16.0.0/12 */
                return 0;
        if (a[0] == 192 && a[1] == 168)                                         /* 192.168.0.0/16 */
                return 0;
        if (a[0] == 192 && a[1] == 0 && (a[2] == 0 || a[2] == 2))               /* 192.0.0.0/24, TEST-NET-1 */
                return 0;
        if (a[0] == 198 && (a[1] & 0xfe) == 18)                                 /* 198.18.0.0/15 */
                return 0;
        if (a[0] == 198 && a[1] == 51 && a[2] == 100)                           /* TEST-NET-2 */
                return 0;
        if (a[0] == 203 && a[1] == 0 && a[2] == 113)                            /* TEST-NET-3 */
                return 0;

        return 1;
}

/* The verifier does not allow offsets selected at runtime without CAP_PERFMON. Keep the compiler from
 * merging the branches below into one with such offsets. */
#define CLAT_KEEP_BRANCH(n) __asm__ __volatile__("" : : "i" (n) : "memory")

#define CLAT_EMBED_CASE(n, a, b, c, d)                                          \
        case n:                                                                 \
                ret[a] = v4[0]; ret[b] = v4[1]; ret[c] = v4[2]; ret[d] = v4[3]; \
                CLAT_KEEP_BRANCH(n);                                            \
                break

#define CLAT_EXTRACT_CASE(n, a, b, c, d)                                        \
        case n:                                                                 \
                ret[0] = v6[a]; ret[1] = v6[b]; ret[2] = v6[c]; ret[3] = v6[d]; \
                CLAT_KEEP_BRANCH(n);                                            \
                break

/* RFC 6052 section 2.2: embed an IPv4 address into an IPv6 address within the NAT64 prefix. Byte 8 (bits
 * 64 to 71) is reserved and must be zero. The prefix must be masked to its length already, and the length be
 * one of 32, 40, 48, 56, 64 or 96. */
CLAT_INLINE void clat_ipv4_embed(
                const unsigned char *prefix,
                unsigned int prefix_len,
                const unsigned char *v4,
                unsigned char *ret) {

        __builtin_memcpy(ret, prefix, 16);

        switch (prefix_len) {
        CLAT_EMBED_CASE(32, 4, 5, 6, 7);
        CLAT_EMBED_CASE(40, 5, 6, 7, 9);
        CLAT_EMBED_CASE(48, 6, 7, 9, 10);
        CLAT_EMBED_CASE(56, 7, 9, 10, 11);
        CLAT_EMBED_CASE(64, 9, 10, 11, 12);
        CLAT_EMBED_CASE(96, 12, 13, 14, 15);
        }
}

/* Reverse of clat_ipv4_embed() */
CLAT_INLINE void clat_ipv4_extract(const unsigned char *v6, unsigned int prefix_len, unsigned char *ret) {
        __builtin_memset(ret, 0, 4);

        switch (prefix_len) {
        CLAT_EXTRACT_CASE(32, 4, 5, 6, 7);
        CLAT_EXTRACT_CASE(40, 5, 6, 7, 9);
        CLAT_EXTRACT_CASE(48, 6, 7, 9, 10);
        CLAT_EXTRACT_CASE(56, 7, 9, 10, 11);
        CLAT_EXTRACT_CASE(64, 9, 10, 11, 12);
        CLAT_EXTRACT_CASE(96, 12, 13, 14, 15);
        }
}

typedef enum ClatICMPResult {
        CLAT_ICMP_DROP,         /* must not be translated */
        CLAT_ICMP_ECHO,         /* echo request or reply, only the type changes */
        CLAT_ICMP_ERROR,        /* error message, the quoted packet has to be translated as well */
} ClatICMPResult;

/* RFC 1191 section 7.1: guess the path MTU when an ICMPv4 "fragmentation needed" message does not carry it:
 * the greatest plateau that is smaller than the length of the packet that did not fit. */
CLAT_INLINE unsigned int clat_mtu_plateau(unsigned int len) {
        if (len > 32000)
                return 32000;
        if (len > 17914)
                return 17914;
        if (len > 8166)
                return 8166;
        if (len > 4352)
                return 4352;
        if (len > 2002)
                return 2002;
        if (len > 1492)
                return 1492;

        return CLAT_IPV6_MIN_MTU; /* smaller values are raised to this anyway */
}

/* RFC 7915 section 4.2. Translates the 8 byte header of an ICMPv4 message to ICMPv6. The checksum of the
 * returned header is zero, and the identifier and sequence number of echo messages are copied. For errors,
 * quoted_len is the total length of the quoted IPv4 packet, and mtu the MTU of the IPv6 link. */
CLAT_INLINE ClatICMPResult clat_icmp_4to6(
                const unsigned char *in,
                unsigned int quoted_len,
                unsigned int mtu,
                unsigned char *ret) {

        unsigned int type = in[0], code = in[1], value = 0;
        unsigned char type6, code6 = 0;

        __builtin_memset(ret, 0, 8);

        switch (type) {
        case 8: /* echo request */
        case 0: /* echo reply */
                __builtin_memcpy(ret, in, 8);
                ret[0] = type == 8 ? 128 : 129;
                ret[2] = ret[3] = 0;
                return CLAT_ICMP_ECHO;

        case 3: /* destination unreachable */
                type6 = 1;
                switch (code) {
                case 0: case 1: case 5: case 6: case 7: case 8: case 11: case 12:
                        code6 = 0; /* no route to destination */
                        break;
                case 2: /* protocol unreachable → parameter problem, unrecognized next header */
                        type6 = 4;
                        code6 = 1;
                        value = 6;
                        break;
                case 3:
                        code6 = 4; /* port unreachable */
                        break;
                case 4: { /* fragmentation needed → packet too big */
                        unsigned int m = ((unsigned int) in[6] << 8) | in[7];

                        type6 = 2;
                        code6 = 0;
                        value = m == 0 ? clat_mtu_plateau(quoted_len) : m + 20;
                        if (mtu > 0 && value > mtu)
                                value = mtu;
                        if (value < CLAT_IPV6_MIN_MTU)
                                value = CLAT_IPV6_MIN_MTU;
                        break;
                }
                case 9: case 10: case 13: case 15:
                        code6 = 1; /* administratively prohibited */
                        break;
                default:
                        return CLAT_ICMP_DROP;
                }
                break;

        case 11: /* time exceeded */
                type6 = 3;
                code6 = (unsigned char) code;
                break;

        case 12: /* parameter problem */
                if (code != 0 && code != 2)
                        return CLAT_ICMP_DROP;

                type6 = 4;
                code6 = 0;
                switch (in[4]) { /* RFC 7915 figure 3 */
                case 0: case 1:
                        value = in[4];
                        break;
                case 2: case 3:
                        value = 4;
                        break;
                case 8:
                        value = 7;
                        break;
                case 9:
                        value = 6;
                        break;
                case 12: case 13: case 14: case 15:
                        value = 8;
                        break;
                case 16: case 17: case 18: case 19:
                        value = 24;
                        break;
                default:
                        return CLAT_ICMP_DROP;
                }
                break;

        default:
                return CLAT_ICMP_DROP;
        }

        ret[0] = type6;
        ret[1] = code6;
        ret[4] = (unsigned char) (value >> 24);
        ret[5] = (unsigned char) (value >> 16);
        ret[6] = (unsigned char) (value >> 8);
        ret[7] = (unsigned char) value;
        return CLAT_ICMP_ERROR;
}

/* RFC 7915 section 5.2. Translates the 8 byte header of an ICMPv6 message to ICMPv4. The checksum of the
 * returned header is zero. mtu is the MTU of the IPv6 link. The length attribute of RFC 4884 is cleared, i.e.
 * extensions of the original message are not announced in the translated one. */
CLAT_INLINE ClatICMPResult clat_icmp_6to4(const unsigned char *in, unsigned int mtu, unsigned char *ret) {
        unsigned int type = in[0], code = in[1];
        unsigned char type4, code4 = 0;

        __builtin_memset(ret, 0, 8);

        switch (type) {
        case 128: /* echo request */
        case 129: /* echo reply */
                __builtin_memcpy(ret, in, 8);
                ret[0] = type == 128 ? 8 : 0;
                ret[2] = ret[3] = 0;
                return CLAT_ICMP_ECHO;

        case 1: /* destination unreachable */
                type4 = 3;
                switch (code) {
                case 0: case 2: case 3:
                        code4 = 1; /* host unreachable */
                        break;
                case 1:
                        code4 = 10; /* administratively prohibited */
                        break;
                case 4:
                        code4 = 3; /* port unreachable */
                        break;
                default:
                        return CLAT_ICMP_DROP;
                }
                break;

        case 2: { /* packet too big → fragmentation needed */
                unsigned int m = ((unsigned int) in[4] << 24) | ((unsigned int) in[5] << 16) |
                                 ((unsigned int) in[6] << 8) | in[7];

                type4 = 3;
                code4 = 4;

                /* RFC 8201 section 4: nothing may reduce the path MTU below the IPv6 minimum MTU */
                if (m < CLAT_IPV6_MIN_MTU)
                        m = CLAT_IPV6_MIN_MTU;
                if (mtu >= CLAT_IPV6_MIN_MTU && m > mtu)
                        m = mtu;
                if (m > 0xffff)
                        m = 0xffff;
                /* Report a size at which fragments of a larger datagram fit as well, as the host
                 * fragments to the path MTU */
                m -= CLAT_MTU_OVERHEAD;

                ret[6] = (unsigned char) (m >> 8);
                ret[7] = (unsigned char) m;
                break;
        }

        case 3: /* time exceeded */
                type4 = 11;
                code4 = (unsigned char) code;
                break;

        case 4: /* parameter problem */
                if (code == 1) { /* unrecognized next header → protocol unreachable */
                        type4 = 3;
                        code4 = 2;
                        break;
                }
                if (code != 0 || in[4] != 0 || in[5] != 0 || in[6] != 0)
                        return CLAT_ICMP_DROP;

                type4 = 12;
                code4 = 0;
                switch (in[7]) { /* RFC 7915 figure 6, the pointer is the first byte of the rest */
                case 0:
                        ret[4] = 0;
                        break;
                case 1:
                        ret[4] = 1;
                        break;
                case 4: case 5:
                        ret[4] = 2;
                        break;
                case 6:
                        ret[4] = 9;
                        break;
                case 7:
                        ret[4] = 8;
                        break;
                default:
                        if (in[7] >= 8 && in[7] <= 23)
                                ret[4] = 12;
                        else if (in[7] >= 24 && in[7] <= 39)
                                ret[4] = 16;
                        else
                                return CLAT_ICMP_DROP;
                }
                break;

        default:
                return CLAT_ICMP_DROP;
        }

        ret[0] = type4;
        ret[1] = code4;
        return CLAT_ICMP_ERROR;
}
