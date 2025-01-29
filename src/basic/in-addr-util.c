/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "in-addr-util.h"
#include "logarithm.h"
#include "macro.h"
#include "parse-util.h"
#include "random-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strxcpyx.h"

bool in4_addr_is_null(const struct in_addr *a) {
        assert(a);

        return a->s_addr == 0;
}

bool in6_addr_is_null(const struct in6_addr *a) {
        assert(a);

        return IN6_IS_ADDR_UNSPECIFIED(a);
}

int in_addr_is_null(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_null(&u->in);

        if (family == AF_INET6)
                return in6_addr_is_null(&u->in6);

        return -EAFNOSUPPORT;
}

bool in4_addr_is_link_local(const struct in_addr *a) {
        assert(a);

        return (be32toh(a->s_addr) & UINT32_C(0xFFFF0000)) == (UINT32_C(169) << 24 | UINT32_C(254) << 16);
}

bool in4_addr_is_link_local_dynamic(const struct in_addr *a) {
        assert(a);

        if (!in4_addr_is_link_local(a))
                return false;

        /* 169.254.0.0/24 and 169.254.255.0/24 must not be used for the dynamic IPv4LL assignment.
         * See RFC 3927 Section 2.1:
         * The IPv4 prefix 169.254/16 is registered with the IANA for this purpose. The first 256 and last
         * 256 addresses in the 169.254/16 prefix are reserved for future use and MUST NOT be selected by a
         * host using this dynamic configuration mechanism. */
        return !IN_SET(be32toh(a->s_addr) & 0x0000FF00U, 0x0000U, 0xFF00U);
}

bool in6_addr_is_link_local(const struct in6_addr *a) {
        assert(a);

        return IN6_IS_ADDR_LINKLOCAL(a);
}

int in_addr_is_link_local(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_link_local(&u->in);

        if (family == AF_INET6)
                return in6_addr_is_link_local(&u->in6);

        return -EAFNOSUPPORT;
}

bool in6_addr_is_link_local_all_nodes(const struct in6_addr *a) {
        assert(a);

        /* ff02::1 */
        return be32toh(a->s6_addr32[0]) == UINT32_C(0xff020000) &&
                a->s6_addr32[1] == 0 &&
                a->s6_addr32[2] == 0 &&
                be32toh(a->s6_addr32[3]) == UINT32_C(0x00000001);
}

bool in4_addr_is_multicast(const struct in_addr *a) {
        assert(a);

        return IN_MULTICAST(be32toh(a->s_addr));
}

bool in6_addr_is_multicast(const struct in6_addr *a) {
        assert(a);

        return IN6_IS_ADDR_MULTICAST(a);
}

int in_addr_is_multicast(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_multicast(&u->in);

        if (family == AF_INET6)
                return in6_addr_is_multicast(&u->in6);

        return -EAFNOSUPPORT;
}

bool in4_addr_is_local_multicast(const struct in_addr *a) {
        assert(a);

        return (be32toh(a->s_addr) & UINT32_C(0xffffff00)) == UINT32_C(0xe0000000);
}

bool in4_addr_is_localhost(const struct in_addr *a) {
        assert(a);

        /* All of 127.x.x.x is localhost. */
        return (be32toh(a->s_addr) & UINT32_C(0xFF000000)) == UINT32_C(127) << 24;
}

bool in4_addr_is_non_local(const struct in_addr *a) {
        /* Whether the address is not null and not localhost.
         *
         * As such, it is suitable to configure as DNS/NTP server from DHCP. */
        return !in4_addr_is_null(a) &&
               !in4_addr_is_localhost(a);
}

int in_addr_is_localhost(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_localhost(&u->in);

        if (family == AF_INET6)
                return IN6_IS_ADDR_LOOPBACK(&u->in6);

        return -EAFNOSUPPORT;
}

int in_addr_is_localhost_one(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                /* 127.0.0.1 */
                return be32toh(u->in.s_addr) == UINT32_C(0x7F000001);

        if (family == AF_INET6)
                return IN6_IS_ADDR_LOOPBACK(&u->in6);

        return -EAFNOSUPPORT;
}

bool in6_addr_is_ipv4_mapped_address(const struct in6_addr *a) {
        return a->s6_addr32[0] == 0 &&
                a->s6_addr32[1] == 0 &&
                a->s6_addr32[2] == htobe32(UINT32_C(0x0000ffff));
}

bool in4_addr_equal(const struct in_addr *a, const struct in_addr *b) {
        assert(a);
        assert(b);

        return a->s_addr == b->s_addr;
}

bool in6_addr_equal(const struct in6_addr *a, const struct in6_addr *b) {
        assert(a);
        assert(b);

        return IN6_ARE_ADDR_EQUAL(a, b);
}

int in_addr_equal(int family, const union in_addr_union *a, const union in_addr_union *b) {
        assert(a);
        assert(b);

        if (family == AF_INET)
                return in4_addr_equal(&a->in, &b->in);

        if (family == AF_INET6)
                return in6_addr_equal(&a->in6, &b->in6);

        return -EAFNOSUPPORT;
}

bool in4_addr_prefix_intersect(
                const struct in_addr *a,
                unsigned aprefixlen,
                const struct in_addr *b,
                unsigned bprefixlen) {

        assert(a);
        assert(b);

        unsigned m = MIN3(aprefixlen, bprefixlen, (unsigned) (sizeof(struct in_addr) * 8));
        if (m == 0)
                return true; /* Let's return earlier, to avoid shift by 32. */

        uint32_t x = be32toh(a->s_addr ^ b->s_addr);
        uint32_t n = 0xFFFFFFFFUL << (32 - m);
        return (x & n) == 0;
}

bool in6_addr_prefix_intersect(
                const struct in6_addr *a,
                unsigned aprefixlen,
                const struct in6_addr *b,
                unsigned bprefixlen) {

        assert(a);
        assert(b);

        unsigned m = MIN3(aprefixlen, bprefixlen, (unsigned) (sizeof(struct in6_addr) * 8));
        if (m == 0)
                return true;

        for (size_t i = 0; i < sizeof(struct in6_addr); i++) {
                uint8_t x = a->s6_addr[i] ^ b->s6_addr[i];
                uint8_t n = m < 8 ? (0xFF << (8 - m)) : 0xFF;
                if ((x & n) != 0)
                        return false;

                if (m <= 8)
                        break;

                m -= 8;
        }

        return true;
}

int in_addr_prefix_intersect(
                int family,
                const union in_addr_union *a,
                unsigned aprefixlen,
                const union in_addr_union *b,
                unsigned bprefixlen) {

        assert(a);
        assert(b);

        /* Checks whether there are any addresses that are in both networks. */

        if (family == AF_INET)
                return in4_addr_prefix_intersect(&a->in, aprefixlen, &b->in, bprefixlen);

        if (family == AF_INET6)
                return in6_addr_prefix_intersect(&a->in6, aprefixlen, &b->in6, bprefixlen);

        return -EAFNOSUPPORT;
}

int in_addr_prefix_next(int family, union in_addr_union *u, unsigned prefixlen) {
        assert(u);

        /* Increases the network part of an address by one. Returns 0 if that succeeds, or -ERANGE if
         * this overflows. */

        return in_addr_prefix_nth(family, u, prefixlen, 1);
}

/*
 * Calculates the nth prefix of size prefixlen starting from the address denoted by u.
 *
 * On success 0 will be returned and the calculated prefix will be available in
 * u. In case the calculation cannot be performed (invalid prefix length,
 * overflows would occur) -ERANGE is returned. If the address family given isn't
 * supported -EAFNOSUPPORT will be returned.
 *
 * Examples:
 *   - in_addr_prefix_nth(AF_INET, 192.168.0.0, 24, 2), returns 0, writes 192.168.2.0 to u
 *   - in_addr_prefix_nth(AF_INET, 192.168.0.0, 24, 0), returns 0, no data written
 *   - in_addr_prefix_nth(AF_INET, 255.255.255.0, 24, 1), returns -ERANGE, no data written
 *   - in_addr_prefix_nth(AF_INET, 255.255.255.0, 0, 1), returns -ERANGE, no data written
 *   - in_addr_prefix_nth(AF_INET6, 2001:db8, 64, 0xff00) returns 0, writes 2001:0db8:0000:ff00:: to u
 */
int in_addr_prefix_nth(int family, union in_addr_union *u, unsigned prefixlen, uint64_t nth) {
        assert(u);

        if (prefixlen <= 0)
                return -ERANGE;

        if (family == AF_INET) {
                uint32_t c, n, t;

                if (prefixlen > 32)
                        return -ERANGE;

                c = be32toh(u->in.s_addr);

                t = nth << (32 - prefixlen);

                /* Check for wrap */
                if (c > UINT32_MAX - t)
                        return -ERANGE;

                n = c + t;

                n &= UINT32_C(0xFFFFFFFF) << (32 - prefixlen);
                u->in.s_addr = htobe32(n);
                return 0;
        }

        if (family == AF_INET6) {
                bool overflow = false;

                if (prefixlen > 128)
                        return -ERANGE;

                for (unsigned i = 16; i > 0; i--) {
                        unsigned t, j = i - 1, p = j * 8;

                        if (p >= prefixlen) {
                                u->in6.s6_addr[j] = 0;
                                continue;
                        }

                        if (prefixlen - p < 8) {
                                u->in6.s6_addr[j] &= 0xff << (8 - (prefixlen - p));
                                t = u->in6.s6_addr[j] + ((nth & 0xff) << (8 - (prefixlen - p)));
                                nth >>= prefixlen - p;
                        } else {
                                t = u->in6.s6_addr[j] + (nth & 0xff) + overflow;
                                nth >>= 8;
                        }

                        overflow = t > UINT8_MAX;
                        u->in6.s6_addr[j] = (uint8_t) (t & 0xff);
                }

                if (overflow || nth != 0)
                        return -ERANGE;

                return 0;
        }

        return -EAFNOSUPPORT;
}

int in_addr_random_prefix(
                int family,
                union in_addr_union *u,
                unsigned prefixlen_fixed_part,
                unsigned prefixlen) {

        assert(u);

        /* Random network part of an address by one. */

        if (prefixlen <= 0)
                return 0;

        if (family == AF_INET) {
                uint32_t c, n;

                if (prefixlen_fixed_part > 32)
                        prefixlen_fixed_part = 32;
                if (prefixlen > 32)
                        prefixlen = 32;
                if (prefixlen_fixed_part >= prefixlen)
                        return -EINVAL;

                c = be32toh(u->in.s_addr);
                c &= ((UINT32_C(1) << prefixlen_fixed_part) - 1) << (32 - prefixlen_fixed_part);

                random_bytes(&n, sizeof(n));
                n &= ((UINT32_C(1) << (prefixlen - prefixlen_fixed_part)) - 1) << (32 - prefixlen);

                u->in.s_addr = htobe32(n | c);
                return 1;
        }

        if (family == AF_INET6) {
                struct in6_addr n;
                unsigned i, j;

                if (prefixlen_fixed_part > 128)
                        prefixlen_fixed_part = 128;
                if (prefixlen > 128)
                        prefixlen = 128;
                if (prefixlen_fixed_part >= prefixlen)
                        return -EINVAL;

                random_bytes(&n, sizeof(n));

                for (i = 0; i < 16; i++) {
                        uint8_t mask_fixed_part = 0, mask = 0;

                        if (i < (prefixlen_fixed_part + 7) / 8) {
                                if (i < prefixlen_fixed_part / 8)
                                        mask_fixed_part = 0xffu;
                                else {
                                        j = prefixlen_fixed_part % 8;
                                        mask_fixed_part = ((UINT8_C(1) << (j + 1)) - 1) << (8 - j);
                                }
                        }

                        if (i < (prefixlen + 7) / 8) {
                                if (i < prefixlen / 8)
                                        mask = 0xffu ^ mask_fixed_part;
                                else {
                                        j = prefixlen % 8;
                                        mask = (((UINT8_C(1) << (j + 1)) - 1) << (8 - j)) ^ mask_fixed_part;
                                }
                        }

                        u->in6.s6_addr[i] &= mask_fixed_part;
                        u->in6.s6_addr[i] |= n.s6_addr[i] & mask;
                }

                return 1;
        }

        return -EAFNOSUPPORT;
}

int in_addr_prefix_range(
                int family,
                const union in_addr_union *in,
                unsigned prefixlen,
                union in_addr_union *ret_start,
                union in_addr_union *ret_end) {

        union in_addr_union start, end;
        int r;

        assert(in);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        if (ret_start) {
                start = *in;
                r = in_addr_prefix_nth(family, &start, prefixlen, 0);
                if (r < 0)
                        return r;
        }

        if (ret_end) {
                end = *in;
                r = in_addr_prefix_nth(family, &end, prefixlen, 1);
                if (r < 0)
                        return r;
        }

        if (ret_start)
                *ret_start = start;
        if (ret_end)
                *ret_end = end;

        return 0;
}

int in_addr_to_string(int family, const union in_addr_union *u, char **ret) {
        _cleanup_free_ char *x = NULL;
        size_t l;

        assert(u);
        assert(ret);

        if (family == AF_INET)
                l = INET_ADDRSTRLEN;
        else if (family == AF_INET6)
                l = INET6_ADDRSTRLEN;
        else
                return -EAFNOSUPPORT;

        x = new(char, l);
        if (!x)
                return -ENOMEM;

        errno = 0;
        if (!typesafe_inet_ntop(family, u, x, l))
                return errno_or_else(EINVAL);

        *ret = TAKE_PTR(x);
        return 0;
}

int in_addr_prefix_to_string(
                int family,
                const union in_addr_union *u,
                unsigned prefixlen,
                char *buf,
                size_t buf_len) {

        assert(u);
        assert(buf);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        errno = 0;
        if (!typesafe_inet_ntop(family, u, buf, buf_len))
                return errno_or_else(ENOSPC);

        size_t l = strlen(buf);
        if (!snprintf_ok(buf + l, buf_len - l, "/%u", prefixlen))
                return -ENOSPC;
        return 0;
}

int in_addr_port_ifindex_name_to_string(int family, const union in_addr_union *u, uint16_t port, int ifindex, const char *server_name, char **ret) {
        _cleanup_free_ char *ip_str = NULL, *x = NULL;
        int r;

        assert(IN_SET(family, AF_INET, AF_INET6));
        assert(u);
        assert(ret);

        /* Much like in_addr_to_string(), but optionally appends the zone interface index to the address, to properly
         * handle IPv6 link-local addresses. */

        r = in_addr_to_string(family, u, &ip_str);
        if (r < 0)
                return r;

        if (family == AF_INET6) {
                r = in_addr_is_link_local(family, u);
                if (r < 0)
                        return r;
                if (r == 0)
                        ifindex = 0;
        } else
                ifindex = 0; /* For IPv4 address, ifindex is always ignored. */

        if (port == 0 && ifindex == 0 && isempty(server_name)) {
                *ret = TAKE_PTR(ip_str);
                return 0;
        }

        const char *separator = isempty(server_name) ? "" : "#";
        server_name = strempty(server_name);

        if (port > 0) {
                if (family == AF_INET6) {
                        if (ifindex > 0)
                                r = asprintf(&x, "[%s]:%"PRIu16"%%%i%s%s", ip_str, port, ifindex, separator, server_name);
                        else
                                r = asprintf(&x, "[%s]:%"PRIu16"%s%s", ip_str, port, separator, server_name);
                } else
                        r = asprintf(&x, "%s:%"PRIu16"%s%s", ip_str, port, separator, server_name);
        } else {
                if (ifindex > 0)
                        r = asprintf(&x, "%s%%%i%s%s", ip_str, ifindex, separator, server_name);
                else {
                        x = strjoin(ip_str, separator, server_name);
                        r = x ? 0 : -ENOMEM;
                }
        }
        if (r < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(x);
        return 0;
}

int in_addr_from_string(int family, const char *s, union in_addr_union *ret) {
        union in_addr_union buffer;
        assert(s);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        errno = 0;
        if (inet_pton(family, s, ret ?: &buffer) <= 0)
                return errno_or_else(EINVAL);

        return 0;
}

int in_addr_from_string_auto(const char *s, int *ret_family, union in_addr_union *ret) {
        int r;

        assert(s);

        r = in_addr_from_string(AF_INET, s, ret);
        if (r >= 0) {
                if (ret_family)
                        *ret_family = AF_INET;
                return 0;
        }

        r = in_addr_from_string(AF_INET6, s, ret);
        if (r >= 0) {
                if (ret_family)
                        *ret_family = AF_INET6;
                return 0;
        }

        return -EINVAL;
}

unsigned char in4_addr_netmask_to_prefixlen(const struct in_addr *addr) {
        assert(addr);

        return 32U - u32ctz(be32toh(addr->s_addr));
}

/* Calculate an IPv4 netmask from prefix length, for example /8 -> 255.0.0.0. */
struct in_addr* in4_addr_prefixlen_to_netmask(struct in_addr *addr, unsigned char prefixlen) {
        assert(addr);
        assert(prefixlen <= 32);

        /* Shifting beyond 32 is not defined, handle this specially. */
        if (prefixlen == 0)
                addr->s_addr = 0;
        else
                addr->s_addr = htobe32((0xffffffff << (32 - prefixlen)) & 0xffffffff);

        return addr;
}

/* Calculate an IPv6 netmask from prefix length, for example /16 -> ffff::. */
struct in6_addr* in6_addr_prefixlen_to_netmask(struct in6_addr *addr, unsigned char prefixlen) {
        assert(addr);
        assert(prefixlen <= 128);

        for (unsigned i = 0; i < 16; i++) {
                uint8_t mask;

                if (prefixlen >= 8) {
                        mask = 0xFF;
                        prefixlen -= 8;
                } else if (prefixlen > 0) {
                        mask = 0xFF << (8 - prefixlen);
                        prefixlen = 0;
                } else {
                        assert(prefixlen == 0);
                        mask = 0;
                }

                addr->s6_addr[i] = mask;
        }

        return addr;
}

/* Calculate an IPv4 or IPv6 netmask from prefix length, for example /8 -> 255.0.0.0 or /16 -> ffff::. */
int in_addr_prefixlen_to_netmask(int family, union in_addr_union *addr, unsigned char prefixlen) {
        assert(addr);

        switch (family) {
        case AF_INET:
                in4_addr_prefixlen_to_netmask(&addr->in, prefixlen);
                return 0;
        case AF_INET6:
                in6_addr_prefixlen_to_netmask(&addr->in6, prefixlen);
                return 0;
        default:
                return -EAFNOSUPPORT;
        }
}

int in4_addr_default_prefixlen(const struct in_addr *addr, unsigned char *prefixlen) {
        uint8_t msb_octet = *(uint8_t*) addr;

        /* addr may not be aligned, so make sure we only access it byte-wise */

        assert(addr);
        assert(prefixlen);

        if (msb_octet < 128)
                /* class A, leading bits: 0 */
                *prefixlen = 8;
        else if (msb_octet < 192)
                /* class B, leading bits 10 */
                *prefixlen = 16;
        else if (msb_octet < 224)
                /* class C, leading bits 110 */
                *prefixlen = 24;
        else
                /* class D or E, no default prefixlen */
                return -ERANGE;

        return 0;
}

int in4_addr_default_subnet_mask(const struct in_addr *addr, struct in_addr *mask) {
        unsigned char prefixlen;
        int r;

        assert(addr);
        assert(mask);

        r = in4_addr_default_prefixlen(addr, &prefixlen);
        if (r < 0)
                return r;

        in4_addr_prefixlen_to_netmask(mask, prefixlen);
        return 0;
}

int in4_addr_mask(struct in_addr *addr, unsigned char prefixlen) {
        struct in_addr mask;

        assert(addr);

        if (!in4_addr_prefixlen_to_netmask(&mask, prefixlen))
                return -EINVAL;

        addr->s_addr &= mask.s_addr;
        return 0;
}

int in6_addr_mask(struct in6_addr *addr, unsigned char prefixlen) {
        unsigned i;

        for (i = 0; i < 16; i++) {
                uint8_t mask;

                if (prefixlen >= 8) {
                        mask = 0xFF;
                        prefixlen -= 8;
                } else if (prefixlen > 0) {
                        mask = 0xFF << (8 - prefixlen);
                        prefixlen = 0;
                } else {
                        assert(prefixlen == 0);
                        mask = 0;
                }

                addr->s6_addr[i] &= mask;
        }

        return 0;
}

int in_addr_mask(int family, union in_addr_union *addr, unsigned char prefixlen) {
        assert(addr);

        switch (family) {
        case AF_INET:
                return in4_addr_mask(&addr->in, prefixlen);
        case AF_INET6:
                return in6_addr_mask(&addr->in6, prefixlen);
        default:
                return -EAFNOSUPPORT;
        }
}

int in4_addr_prefix_covers_full(
                const struct in_addr *prefix,
                unsigned char prefixlen,
                const struct in_addr *address,
                unsigned char address_prefixlen) {

        struct in_addr masked_prefix, masked_address;
        int r;

        assert(prefix);
        assert(address);

        if (prefixlen > address_prefixlen)
                return false;

        masked_prefix = *prefix;
        r = in4_addr_mask(&masked_prefix, prefixlen);
        if (r < 0)
                return r;

        masked_address = *address;
        r = in4_addr_mask(&masked_address, prefixlen);
        if (r < 0)
                return r;

        return in4_addr_equal(&masked_prefix, &masked_address);
}

int in6_addr_prefix_covers_full(
                const struct in6_addr *prefix,
                unsigned char prefixlen,
                const struct in6_addr *address,
                unsigned char address_prefixlen) {

        struct in6_addr masked_prefix, masked_address;
        int r;

        assert(prefix);
        assert(address);

        if (prefixlen > address_prefixlen)
                return false;

        masked_prefix = *prefix;
        r = in6_addr_mask(&masked_prefix, prefixlen);
        if (r < 0)
                return r;

        masked_address = *address;
        r = in6_addr_mask(&masked_address, prefixlen);
        if (r < 0)
                return r;

        return in6_addr_equal(&masked_prefix, &masked_address);
}

int in_addr_prefix_covers_full(
                int family,
                const union in_addr_union *prefix,
                unsigned char prefixlen,
                const union in_addr_union *address,
                unsigned char address_prefixlen) {

        assert(prefix);
        assert(address);

        switch (family) {
        case AF_INET:
                return in4_addr_prefix_covers_full(&prefix->in, prefixlen, &address->in, address_prefixlen);
        case AF_INET6:
                return in6_addr_prefix_covers_full(&prefix->in6, prefixlen, &address->in6, address_prefixlen);
        default:
                return -EAFNOSUPPORT;
        }
}

int in_addr_parse_prefixlen(int family, const char *p, unsigned char *ret) {
        uint8_t u;
        int r;

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        r = safe_atou8(p, &u);
        if (r < 0)
                return r;

        if (u > FAMILY_ADDRESS_SIZE(family) * 8)
                return -ERANGE;

        *ret = u;
        return 0;
}

int in_addr_prefix_from_string(
                const char *p,
                int family,
                union in_addr_union *ret_prefix,
                unsigned char *ret_prefixlen) {

        _cleanup_free_ char *str = NULL;
        union in_addr_union buffer;
        const char *e, *l;
        unsigned char k;
        int r;

        assert(p);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        e = strchr(p, '/');
        if (e) {
                str = strndup(p, e - p);
                if (!str)
                        return -ENOMEM;

                l = str;
        } else
                l = p;

        r = in_addr_from_string(family, l, &buffer);
        if (r < 0)
                return r;

        if (e) {
                r = in_addr_parse_prefixlen(family, e+1, &k);
                if (r < 0)
                        return r;
        } else
                k = FAMILY_ADDRESS_SIZE(family) * 8;

        if (ret_prefix)
                *ret_prefix = buffer;
        if (ret_prefixlen)
                *ret_prefixlen = k;

        return 0;
}

int in_addr_prefix_from_string_auto_full(
                const char *p,
                InAddrPrefixLenMode mode,
                int *ret_family,
                union in_addr_union *ret_prefix,
                unsigned char *ret_prefixlen) {

        _cleanup_free_ char *str = NULL;
        union in_addr_union buffer;
        const char *e, *l;
        unsigned char k;
        int family, r;

        assert(p);

        e = strchr(p, '/');
        if (e) {
                str = strndup(p, e - p);
                if (!str)
                        return -ENOMEM;

                l = str;
        } else
                l = p;

        r = in_addr_from_string_auto(l, &family, &buffer);
        if (r < 0)
                return r;

        if (e) {
                r = in_addr_parse_prefixlen(family, e+1, &k);
                if (r < 0)
                        return r;
        } else
                switch (mode) {
                case PREFIXLEN_FULL:
                        k = FAMILY_ADDRESS_SIZE(family) * 8;
                        break;
                case PREFIXLEN_REFUSE:
                        return -ENOANO; /* To distinguish this error from others. */
                default:
                        assert_not_reached();
                }

        if (ret_family)
                *ret_family = family;
        if (ret_prefix)
                *ret_prefix = buffer;
        if (ret_prefixlen)
                *ret_prefixlen = k;

        return 0;
}

void in_addr_hash_func(const union in_addr_union *u, int family, struct siphash *state) {
        assert(u);
        assert(state);

        siphash24_compress(u->bytes, FAMILY_ADDRESS_SIZE(family), state);
}

void in_addr_data_hash_func(const struct in_addr_data *a, struct siphash *state) {
        assert(a);
        assert(state);

        siphash24_compress_typesafe(a->family, state);
        in_addr_hash_func(&a->address, a->family, state);
}

int in_addr_data_compare_func(const struct in_addr_data *x, const struct in_addr_data *y) {
        int r;

        assert(x);
        assert(y);

        r = CMP(x->family, y->family);
        if (r != 0)
                return r;

        return memcmp(&x->address, &y->address, FAMILY_ADDRESS_SIZE(x->family));
}

DEFINE_HASH_OPS(
        in_addr_data_hash_ops,
        struct in_addr_data,
        in_addr_data_hash_func,
        in_addr_data_compare_func);

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        in_addr_data_hash_ops_free,
        struct in_addr_data,
        in_addr_data_hash_func,
        in_addr_data_compare_func,
        free);

void in6_addr_hash_func(const struct in6_addr *addr, struct siphash *state) {
        assert(addr);
        assert(state);

        siphash24_compress_typesafe(*addr, state);
}

int in6_addr_compare_func(const struct in6_addr *a, const struct in6_addr *b) {
        assert(a);
        assert(b);

        return memcmp(a, b, sizeof(*a));
}

DEFINE_HASH_OPS(
        in6_addr_hash_ops,
        struct in6_addr,
        in6_addr_hash_func,
        in6_addr_compare_func);

DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(
        in6_addr_hash_ops_free,
        struct in6_addr,
        in6_addr_hash_func,
        in6_addr_compare_func,
        free);
