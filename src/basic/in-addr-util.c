/* SPDX-License-Identifier: LGPL-2.1+ */

#include <arpa/inet.h>
#include <endian.h>
#include <errno.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>

#include "alloc-util.h"
#include "in-addr-util.h"
#include "macro.h"
#include "parse-util.h"
#include "util.h"

bool in4_addr_is_null(const struct in_addr *a) {
        assert(a);

        return a->s_addr == 0;
}

int in_addr_is_null(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_null(&u->in);

        if (family == AF_INET6)
                return IN6_IS_ADDR_UNSPECIFIED(&u->in6);

        return -EAFNOSUPPORT;
}

bool in4_addr_is_link_local(const struct in_addr *a) {
        assert(a);

        return (be32toh(a->s_addr) & UINT32_C(0xFFFF0000)) == (UINT32_C(169) << 24 | UINT32_C(254) << 16);
}

int in_addr_is_link_local(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_link_local(&u->in);

        if (family == AF_INET6)
                return IN6_IS_ADDR_LINKLOCAL(&u->in6);

        return -EAFNOSUPPORT;
}

int in_addr_is_multicast(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return IN_MULTICAST(be32toh(u->in.s_addr));

        if (family == AF_INET6)
                return IN6_IS_ADDR_MULTICAST(&u->in6);

        return -EAFNOSUPPORT;
}

bool in4_addr_is_localhost(const struct in_addr *a) {
        assert(a);

        /* All of 127.x.x.x is localhost. */
        return (be32toh(a->s_addr) & UINT32_C(0xFF000000)) == UINT32_C(127) << 24;
}

int in_addr_is_localhost(int family, const union in_addr_union *u) {
        assert(u);

        if (family == AF_INET)
                return in4_addr_is_localhost(&u->in);

        if (family == AF_INET6)
                return IN6_IS_ADDR_LOOPBACK(&u->in6);

        return -EAFNOSUPPORT;
}

int in_addr_equal(int family, const union in_addr_union *a, const union in_addr_union *b) {
        assert(a);
        assert(b);

        if (family == AF_INET)
                return a->in.s_addr == b->in.s_addr;

        if (family == AF_INET6)
                return
                        a->in6.s6_addr32[0] == b->in6.s6_addr32[0] &&
                        a->in6.s6_addr32[1] == b->in6.s6_addr32[1] &&
                        a->in6.s6_addr32[2] == b->in6.s6_addr32[2] &&
                        a->in6.s6_addr32[3] == b->in6.s6_addr32[3];

        return -EAFNOSUPPORT;
}

int in_addr_prefix_intersect(
                int family,
                const union in_addr_union *a,
                unsigned aprefixlen,
                const union in_addr_union *b,
                unsigned bprefixlen) {

        unsigned m;

        assert(a);
        assert(b);

        /* Checks whether there are any addresses that are in both
         * networks */

        m = MIN(aprefixlen, bprefixlen);

        if (family == AF_INET) {
                uint32_t x, nm;

                x = be32toh(a->in.s_addr ^ b->in.s_addr);
                nm = (m == 0) ? 0 : 0xFFFFFFFFUL << (32 - m);

                return (x & nm) == 0;
        }

        if (family == AF_INET6) {
                unsigned i;

                if (m > 128)
                        m = 128;

                for (i = 0; i < 16; i++) {
                        uint8_t x, nm;

                        x = a->in6.s6_addr[i] ^ b->in6.s6_addr[i];

                        if (m < 8)
                                nm = 0xFF << (8 - m);
                        else
                                nm = 0xFF;

                        if ((x & nm) != 0)
                                return 0;

                        if (m > 8)
                                m -= 8;
                        else
                                m = 0;
                }

                return 1;
        }

        return -EAFNOSUPPORT;
}

int in_addr_prefix_next(int family, union in_addr_union *u, unsigned prefixlen) {
        assert(u);

        /* Increases the network part of an address by one. Returns
         * positive it that succeeds, or 0 if this overflows. */

        if (prefixlen <= 0)
                return 0;

        if (family == AF_INET) {
                uint32_t c, n;

                if (prefixlen > 32)
                        prefixlen = 32;

                c = be32toh(u->in.s_addr);
                n = c + (1UL << (32 - prefixlen));
                if (n < c)
                        return 0;
                n &= 0xFFFFFFFFUL << (32 - prefixlen);

                u->in.s_addr = htobe32(n);
                return 1;
        }

        if (family == AF_INET6) {
                struct in6_addr add = {}, result;
                uint8_t overflow = 0;
                unsigned i;

                if (prefixlen > 128)
                        prefixlen = 128;

                /* First calculate what we have to add */
                add.s6_addr[(prefixlen-1) / 8] = 1 << (7 - (prefixlen-1) % 8);

                for (i = 16; i > 0; i--) {
                        unsigned j = i - 1;

                        result.s6_addr[j] = u->in6.s6_addr[j] + add.s6_addr[j] + overflow;
                        overflow = (result.s6_addr[j] < u->in6.s6_addr[j]);
                }

                if (overflow)
                        return 0;

                u->in6 = result;
                return 1;
        }

        return -EAFNOSUPPORT;
}

int in_addr_to_string(int family, const union in_addr_union *u, char **ret) {
        char *x;
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
        if (!inet_ntop(family, u, x, l)) {
                free(x);
                return errno > 0 ? -errno : -EINVAL;
        }

        *ret = x;
        return 0;
}

int in_addr_ifindex_to_string(int family, const union in_addr_union *u, int ifindex, char **ret) {
        size_t l;
        char *x;
        int r;

        assert(u);
        assert(ret);

        /* Much like in_addr_to_string(), but optionally appends the zone interface index to the address, to properly
         * handle IPv6 link-local addresses. */

        if (family != AF_INET6)
                goto fallback;
        if (ifindex <= 0)
                goto fallback;

        r = in_addr_is_link_local(family, u);
        if (r < 0)
                return r;
        if (r == 0)
                goto fallback;

        l = INET6_ADDRSTRLEN + 1 + DECIMAL_STR_MAX(ifindex) + 1;
        x = new(char, l);
        if (!x)
                return -ENOMEM;

        errno = 0;
        if (!inet_ntop(family, u, x, l)) {
                free(x);
                return errno > 0 ? -errno : -EINVAL;
        }

        sprintf(strchr(x, 0), "%%%i", ifindex);
        *ret = x;

        return 0;

fallback:
        return in_addr_to_string(family, u, ret);
}

int in_addr_from_string(int family, const char *s, union in_addr_union *ret) {
        union in_addr_union buffer;
        assert(s);

        if (!IN_SET(family, AF_INET, AF_INET6))
                return -EAFNOSUPPORT;

        errno = 0;
        if (inet_pton(family, s, ret ?: &buffer) <= 0)
                return errno > 0 ? -errno : -EINVAL;

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

int in_addr_ifindex_from_string_auto(const char *s, int *family, union in_addr_union *ret, int *ifindex) {
        _cleanup_free_ char *buf = NULL;
        const char *suffix;
        int r, ifi = 0;

        assert(s);
        assert(family);
        assert(ret);

        /* Similar to in_addr_from_string_auto() but also parses an optionally appended IPv6 zone suffix ("scope id")
         * if one is found. */

        suffix = strchr(s, '%');
        if (suffix) {

                if (ifindex) {
                        /* If we shall return the interface index, try to parse it */
                        r = parse_ifindex(suffix + 1, &ifi);
                        if (r < 0) {
                                unsigned u;

                                u = if_nametoindex(suffix + 1);
                                if (u <= 0)
                                        return -errno;

                                ifi = (int) u;
                        }
                }

                buf = strndup(s, suffix - s);
                if (!buf)
                        return -ENOMEM;

                s = buf;
        }

        r = in_addr_from_string_auto(s, family, ret);
        if (r < 0)
                return r;

        if (ifindex)
                *ifindex = ifi;

        return r;
}

unsigned char in4_addr_netmask_to_prefixlen(const struct in_addr *addr) {
        assert(addr);

        return 32 - u32ctz(be32toh(addr->s_addr));
}

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

int in_addr_mask(int family, union in_addr_union *addr, unsigned char prefixlen) {
        assert(addr);

        if (family == AF_INET) {
                struct in_addr mask;

                if (!in4_addr_prefixlen_to_netmask(&mask, prefixlen))
                        return -EINVAL;

                addr->in.s_addr &= mask.s_addr;
                return 0;
        }

        if (family == AF_INET6) {
                unsigned i;

                for (i = 0; i < 16; i++) {
                        uint8_t mask;

                        if (prefixlen >= 8) {
                                mask = 0xFF;
                                prefixlen -= 8;
                        } else {
                                mask = 0xFF << (8 - prefixlen);
                                prefixlen = 0;
                        }

                        addr->in6.s6_addr[i] &= mask;
                }

                return 0;
        }

        return -EAFNOSUPPORT;
}

int in_addr_prefix_covers(int family,
                          const union in_addr_union *prefix,
                          unsigned char prefixlen,
                          const union in_addr_union *address) {

        union in_addr_union masked_prefix, masked_address;
        int r;

        assert(prefix);
        assert(address);

        masked_prefix = *prefix;
        r = in_addr_mask(family, &masked_prefix, prefixlen);
        if (r < 0)
                return r;

        masked_address = *address;
        r = in_addr_mask(family, &masked_address, prefixlen);
        if (r < 0)
                return r;

        return in_addr_equal(family, &masked_prefix, &masked_address);
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

int in_addr_prefix_from_string_internal(
                const char *p,
                bool use_default_prefixlen,
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
        } else if (use_default_prefixlen) {
                if (family == AF_INET) {
                        r = in4_addr_default_prefixlen(&buffer.in, &k);
                        if (r < 0)
                                return r;
                } else
                        k = 0;
        } else
                k = FAMILY_ADDRESS_SIZE(family) * 8;

        if (ret_prefix)
                *ret_prefix = buffer;
        if (ret_prefixlen)
                *ret_prefixlen = k;

        return 0;
}

int in_addr_prefix_from_string_auto_internal(
                const char *p,
                bool use_default_prefixlen,
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
        } else if (use_default_prefixlen) {
                if (family == AF_INET) {
                        r = in4_addr_default_prefixlen(&buffer.in, &k);
                        if (r < 0)
                                return r;
                } else
                        k = 0;
        } else
                k = FAMILY_ADDRESS_SIZE(family) * 8;

        if (ret_family)
                *ret_family = family;
        if (ret_prefix)
                *ret_prefix = buffer;
        if (ret_prefixlen)
                *ret_prefixlen = k;

        return 0;

}

void in_addr_data_hash_func(const void *p, struct siphash *state) {
        const struct in_addr_data *a = p;

        siphash24_compress(&a->family, sizeof(a->family), state);
        siphash24_compress(&a->address, FAMILY_ADDRESS_SIZE(a->family), state);
}

int in_addr_data_compare_func(const void *a, const void *b) {
        const struct in_addr_data *x = a, *y = b;
        int r;

        r = CMP(x->family, y->family);
        if (r != 0)
                return r;

        return memcmp(&x->address, &y->address, FAMILY_ADDRESS_SIZE(x->family));
}

const struct hash_ops in_addr_data_hash_ops = {
        .hash = in_addr_data_hash_func,
        .compare = in_addr_data_compare_func,
};
