/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "hostname-util.h"
#include "in-addr-prefix-util.h"
#include "string-util.h"

static void in_addr_prefix_hash_func(const struct in_addr_prefix *a, struct siphash *state) {
        assert(a);
        assert(state);

        siphash24_compress(&a->family, sizeof(a->family), state);
        siphash24_compress(&a->prefixlen, sizeof(a->prefixlen), state);
        siphash24_compress(&a->address, FAMILY_ADDRESS_SIZE(a->family), state);
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
        _cleanup_set_free_ Set *ipv4_prefixlens = NULL, *ipv6_prefixlens = NULL;
        struct in_addr_prefix *p;
        int r;

        SET_FOREACH(p, prefixes) {
                Set **prefixlens = p->family == AF_INET ? &ipv4_prefixlens : &ipv6_prefixlens;

                r = set_ensure_put(prefixlens, NULL, UINT8_TO_PTR(p->prefixlen + 1));
                if (r < 0)
                        return r;
        }

        SET_FOREACH(p, prefixes) {
                Set **prefixlens = p->family == AF_INET ? &ipv4_prefixlens : &ipv6_prefixlens;
                bool covered = false;
                void *q;

                SET_FOREACH(q, *prefixlens) {
                        uint8_t l = PTR_TO_UINT8(q) - 1;
                        struct in_addr_prefix tmp;

                        if (l >= p->prefixlen)
                                continue;

                        tmp = *p;
                        tmp.prefixlen = l;
                        (void) in_addr_mask(tmp.family, &tmp.address, tmp.prefixlen);

                        if (set_contains(prefixes, &tmp)) {
                                covered = true;
                                break;
                        }
                }

                if (covered) {
                        free(set_remove(prefixes, p));
                        continue;
                }
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
                set_contains(prefixes, &(struct in_addr_prefix) { .family = AF_INET }) &&
                set_contains(prefixes, &(struct in_addr_prefix) { .family = AF_INET6 });
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

        Set **prefixes = data;
        int r;

        assert(prefixes);
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
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) { .family = AF_INET });
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) { .family = AF_INET6 });
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (is_localhost(word)) {
                        /* "localhost" is a shortcut for 127.0.0.0/8 and ::1/128 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) {
                                                .family = AF_INET,
                                                .address.in.s_addr = htobe32(0x7f000000),
                                                .prefixlen = 8 });
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) {
                                                .family = AF_INET6,
                                                .address.in6 = IN6ADDR_LOOPBACK_INIT,
                                                .prefixlen = 128 });
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (streq(word, "link-local")) {
                        /* "link-local" is a shortcut for 169.254.0.0/16 and fe80::/64 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) {
                                                .family = AF_INET,
                                                .address.in.s_addr = htobe32((UINT32_C(169) << 24) | (UINT32_C(254) << 16)),
                                                .prefixlen = 16 });
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) {
                                                .family = AF_INET6,
                                                .address.in6.s6_addr32[0] = htobe32(0xfe800000),
                                                .prefixlen = 64 });
                                if (r < 0)
                                        return log_oom();
                        }

                } else if (streq(word, "multicast")) {
                        /* "multicast" is a shortcut for 224.0.0.0/4 and ff00::/8 */

                        if (ltype != AF_INET6) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) {
                                                .family = AF_INET,
                                                .address.in.s_addr = htobe32((UINT32_C(224) << 24)),
                                                .prefixlen = 4 });
                                if (r < 0)
                                        return log_oom();
                        }

                        if (ltype != AF_INET) {
                                r = in_addr_prefix_add(prefixes, &(struct in_addr_prefix) {
                                                .family = AF_INET6,
                                                .address.in6.s6_addr32[0] = htobe32(0xff000000),
                                                .prefixlen = 8 });
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
                                           "Address prefix is invalid, ignoring assignment: %s", word);
                                continue;
                        }

                        r = in_addr_prefix_add(prefixes, &a);
                        if (r < 0)
                                return log_oom();
                }
        }
}
