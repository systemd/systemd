/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "hostname-util.h"
#include "in-addr-prefix-util.h"
#include "string-util.h"

/* 0.0.0.0/0 */
#define IN_ADDR_PREFIX_IPV4_ANY ((struct in_addr_prefix) { .family = AF_INET })
/* ::/0 */
#define IN_ADDR_PREFIX_IPV6_ANY ((struct in_addr_prefix) { .family = AF_INET6 })
/* 127.0.0.0/8 */
#define IN_ADDR_PREFIX_IPV4_LOCALHOST                                   \
        ((struct in_addr_prefix) {                                      \
                .family = AF_INET,                                      \
                .address.in.s_addr = htobe32(UINT32_C(127) << 24),      \
                .prefixlen = 8,                                         \
        })
/* ::1/128 */
#define IN_ADDR_PREFIX_IPV6_LOCALHOST                                   \
        ((struct in_addr_prefix) {                                      \
                .family = AF_INET6,                                     \
                .address.in6 = IN6ADDR_LOOPBACK_INIT,                   \
                .prefixlen = 128,                                       \
        })
/* 169.254.0.0/16 */
#define IN_ADDR_PREFIX_IPV4_LINKLOCAL                                   \
        ((struct in_addr_prefix) {                                      \
                .family = AF_INET,                                      \
                .address.in.s_addr = htobe32((UINT32_C(169) << 24) |    \
                                             (UINT32_C(254) << 16)),    \
                .prefixlen = 16,                                        \
        })
/* fe80::/64 */
#define IN_ADDR_PREFIX_IPV6_LINKLOCAL                                   \
        ((struct in_addr_prefix) {                                      \
                .family = AF_INET6,                                     \
                .address.in6.s6_addr[0] = 0xfe,                         \
                .address.in6.s6_addr[1] = 0x80,                         \
                .prefixlen = 64,                                        \
        })
/* 224.0.0.0/4 */
#define IN_ADDR_PREFIX_IPV4_MULTICAST                                   \
        ((struct in_addr_prefix) {                                      \
                .family = AF_INET,                                      \
                .address.in.s_addr = htobe32((UINT32_C(224) << 24)),    \
                .prefixlen = 4,                                         \
        })
/* ff00::/8 */
#define IN_ADDR_PREFIX_IPV6_MULTICAST                                   \
        ((struct in_addr_prefix) {                                      \
                .family = AF_INET6,                                     \
                .address.in6.s6_addr[0] = 0xff,                         \
                .prefixlen = 8,                                         \
        })

static void in_addr_prefix_hash_func(const struct in_addr_prefix *a, struct siphash *state) {
        assert(a);
        assert(state);

        siphash24_compress_typesafe(a->family, state);
        siphash24_compress_typesafe(a->prefixlen, state);
        in_addr_hash_func(&a->address, a->family, state);
}

static int in_addr_prefix_compare_func(const struct in_addr_prefix *x, const struct in_addr_prefix *y) {
        int r;

        assert(x);
        assert(y);

        r = CMP(x->family, y->family);
        if (r != 0)
                return r;

        r = CMP(x->prefixlen, y->prefixlen);
        if (r != 0)
                return r;

        return memcmp(&x->address, &y->address, FAMILY_ADDRESS_SIZE(x->family));
}

DEFINE_HASH_OPS(in_addr_prefix_hash_ops, struct in_addr_prefix, in_addr_prefix_hash_func, in_addr_prefix_compare_func);
DEFINE_HASH_OPS_WITH_KEY_DESTRUCTOR(in_addr_prefix_hash_ops_free, struct in_addr_prefix, in_addr_prefix_hash_func, in_addr_prefix_compare_func, free);

int in_addr_prefix_add(Set **prefixes, const struct in_addr_prefix *prefix) {
        struct in_addr_prefix *copy;

        assert(prefixes);
        assert(prefix);
        assert(IN_SET(prefix->family, AF_INET, AF_INET6));

        copy = newdup(struct in_addr_prefix, prefix, 1);
        if (!copy)
                return -ENOMEM;

        (void) in_addr_mask(copy->family, &copy->address, copy->prefixlen);
        return set_ensure_consume(prefixes, &in_addr_prefix_hash_ops_free, copy);
}

int in_addr_prefixes_reduce(Set *prefixes) {
        uint32_t ipv4_prefixlen_bits = 0;
        uint64_t ipv6_prefixlen_bits[128 / sizeof(uint64_t)] = {};
        uint8_t ipv4_prefixlens[32] = {}, ipv6_prefixlens[128] = {};
        bool ipv4_has_any = false, ipv6_has_any = false;
        size_t ipv4_n_prefixlens = 0, ipv6_n_prefixlens = 0;
        struct in_addr_prefix *p;

        SET_FOREACH(p, prefixes)
                switch (p->family) {
                case AF_INET:
                        assert(p->prefixlen <= 32);
                        if (p->prefixlen == 0)
                                ipv4_has_any = true;
                        else
                                ipv4_prefixlen_bits |= UINT32_C(1) << (p->prefixlen - 1);
                        break;
                case AF_INET6:
                        assert(p->prefixlen <= 128);
                        if (p->prefixlen == 0)
                                ipv6_has_any = true;
                        else
                                ipv6_prefixlen_bits[(p->prefixlen - 1) / sizeof(uint64_t)] |=
                                        UINT64_C(1) << ((p->prefixlen - 1) % sizeof(uint64_t));
                        break;
                default:
                        assert_not_reached();
                }

        if (!ipv4_has_any)
                for (size_t i = 0; i < 32; i++)
                        if (ipv4_prefixlen_bits & (UINT32_C(1) << i))
                                ipv4_prefixlens[ipv4_n_prefixlens++] = i + 1;

        if (!ipv6_has_any)
                for (size_t i = 0; i < 128; i++)
                        if (ipv6_prefixlen_bits[i / sizeof(uint64_t)] &
                            (UINT64_C(1) << (i % sizeof(uint64_t))))
                                ipv6_prefixlens[ipv6_n_prefixlens++] = i + 1;

        SET_FOREACH(p, prefixes) {
                uint8_t *prefixlens;
                bool covered;
                size_t *n;

                if (p->prefixlen == 0)
                        continue;

                switch (p->family) {
                case AF_INET:
                        prefixlens = ipv4_prefixlens;
                        n = &ipv4_n_prefixlens;
                        covered = ipv4_has_any;
                        break;
                case AF_INET6:
                        prefixlens = ipv6_prefixlens;
                        n = &ipv6_n_prefixlens;
                        covered = ipv6_has_any;
                        break;
                default:
                        assert_not_reached();
                }

                for (size_t i = 0; i < *n; i++) {
                        struct in_addr_prefix tmp;

                        if (covered)
                                break;

                        if (prefixlens[i] >= p->prefixlen)
                                break;

                        tmp = *p;
                        tmp.prefixlen = prefixlens[i];
                        (void) in_addr_mask(tmp.family, &tmp.address, tmp.prefixlen);

                        covered = set_contains(prefixes, &tmp);
                }

                if (covered)
                        free(set_remove(prefixes, p));
        }

        return 0;
}

int in_addr_prefixes_merge(Set **dest, Set *src) {
        struct in_addr_prefix *p;
        int r;

        assert(dest);

        SET_FOREACH(p, src) {
                r = in_addr_prefix_add(dest, p);
                if (r < 0)
                        return r;
        }

        return 0;
}

bool in_addr_prefixes_is_any(Set *prefixes) {
        return
                set_contains(prefixes, &IN_ADDR_PREFIX_IPV4_ANY) &&
                set_contains(prefixes, &IN_ADDR_PREFIX_IPV6_ANY);
}

int config_parse_in_addr_prefixes(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **prefixes = ASSERT_PTR(data);
        int r;

        assert(IN_SET(ltype, AF_UNSPEC, AF_INET, AF_INET6));

        if (isempty(rvalue)) {
                *prefixes = set_free(*prefixes);
                return 0;
        }

        for (const char *p = rvalue;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r == -ENOMEM)
                        return log_oom();
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Invalid syntax, ignoring: %s", rvalue);
                        return 0;
                }
                if (r == 0)
                        return 0;

                if (streq(word, "any")) {
                        /* "any" is a shortcut for 0.0.0.0/0 and ::/0 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV4_ANY);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV6_ANY);
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (is_localhost(word)) {
                        /* "localhost" is a shortcut for 127.0.0.0/8 and ::1/128 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV4_LOCALHOST);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV6_LOCALHOST);
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (streq(word, "link-local")) {
                        /* "link-local" is a shortcut for 169.254.0.0/16 and fe80::/64 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV4_LINKLOCAL);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV6_LINKLOCAL);
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (streq(word, "multicast")) {
                        /* "multicast" is a shortcut for 224.0.0.0/4 and ff00::/8 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV4_MULTICAST);
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &IN_ADDR_PREFIX_IPV6_MULTICAST);
                                if (r < 0)
                                        return log_oom();
                        }

                } else {
                        struct in_addr_prefix a;

                        if (ltype == AF_UNSPEC)
                                r = in_addr_prefix_from_string_auto(word, &a.family, &a.address, &a.prefixlen);
                        else {
                                a.family = ltype;
                                r = in_addr_prefix_from_string(word, a.family, &a.address, &a.prefixlen);
                        }
                        if (r < 0) {
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Invalid address prefix is specified in [%s] %s=, ignoring assignment: %s",
                                           section, lvalue, word);
                                continue;
                        }

                        r = in_addr_prefix_add(prefixes, &a);
                        if (r < 0)
                                return log_oom();
                }
        }
}
