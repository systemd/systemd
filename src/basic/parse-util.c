/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <inttypes.h>
#include <net/if.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "alloc-util.h"
#include "errno-list.h"
#include "extract-word.h"
#include "locale-util.h"
#include "macro.h"
#include "missing_network.h"
#include "parse-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"

int parse_boolean(const char *v) {
        if (!v)
                return -EINVAL;

        if (STRCASE_IN_SET(v,
                           "1",
                           "yes",
                           "y",
                           "true",
                           "t",
                           "on"))
                return 1;

        if (STRCASE_IN_SET(v,
                           "0",
                           "no",
                           "n",
                           "false",
                           "f",
                           "off"))
                return 0;

        return -EINVAL;
}

int parse_tristate_full(const char *v, const char *third, int *ret) {
        int r;

        if (isempty(v) || streq_ptr(v, third)) { /* Empty string is always taken as the third/invalid/auto state */
                if (ret)
                        *ret = -1;
        } else {
                r = parse_boolean(v);
                if (r < 0)
                        return r;

                if (ret)
                        *ret = r;
        }

        return 0;
}

int parse_pid(const char *s, pid_t* ret_pid) {
        unsigned long ul = 0;
        pid_t pid;
        int r;

        assert(s);

        r = safe_atolu(s, &ul);
        if (r < 0)
                return r;

        pid = (pid_t) ul;

        if ((unsigned long) pid != ul)
                return -ERANGE;

        if (!pid_is_valid(pid))
                return -ERANGE;

        if (ret_pid)
                *ret_pid = pid;
        return 0;
}

int parse_mode(const char *s, mode_t *ret) {
        unsigned m;
        int r;

        assert(s);

        r = safe_atou_full(s, 8 |
                           SAFE_ATO_REFUSE_PLUS_MINUS, /* Leading '+' or even '-' char? that's just weird,
                                                        * refuse. User might have wanted to add mode flags or
                                                        * so, but this parser doesn't allow that, so let's
                                                        * better be safe. */
                           &m);
        if (r < 0)
                return r;
        if (m > 07777)
                return -ERANGE;

        if (ret)
                *ret = m;
        return 0;
}

int parse_ifindex(const char *s) {
        int ifi, r;

        assert(s);

        r = safe_atoi(s, &ifi);
        if (r < 0)
                return r;
        if (ifi <= 0)
                return -EINVAL;

        return ifi;
}

int parse_mtu(int family, const char *s, uint32_t *ret) {
        uint64_t u, m;
        int r;

        r = parse_size(s, 1024, &u);
        if (r < 0)
                return r;

        if (u > UINT32_MAX)
                return -ERANGE;

        switch (family) {
        case AF_INET:
                m = IPV4_MIN_MTU; /* This is 68 */
                break;
        case AF_INET6:
                m = IPV6_MIN_MTU; /* This is 1280 */
                break;
        default:
                m = 0;
        }

        if (u < m)
                return -ERANGE;

        *ret = (uint32_t) u;
        return 0;
}

int parse_size(const char *t, uint64_t base, uint64_t *size) {

        /* Soo, sometimes we want to parse IEC binary suffixes, and
         * sometimes SI decimal suffixes. This function can parse
         * both. Which one is the right way depends on the
         * context. Wikipedia suggests that SI is customary for
         * hardware metrics and network speeds, while IEC is
         * customary for most data sizes used by software and volatile
         * (RAM) memory. Hence be careful which one you pick!
         *
         * In either case we use just K, M, G as suffix, and not Ki,
         * Mi, Gi or so (as IEC would suggest). That's because that's
         * frickin' ugly. But this means you really need to make sure
         * to document which base you are parsing when you use this
         * call. */

        struct table {
                const char *suffix;
                unsigned long long factor;
        };

        static const struct table iec[] = {
                { "E", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "P", 1024ULL*1024ULL*1024ULL*1024ULL*1024ULL },
                { "T", 1024ULL*1024ULL*1024ULL*1024ULL },
                { "G", 1024ULL*1024ULL*1024ULL },
                { "M", 1024ULL*1024ULL },
                { "K", 1024ULL },
                { "B", 1ULL },
                { "",  1ULL },
        };

        static const struct table si[] = {
                { "E", 1000ULL*1000ULL*1000ULL*1000ULL*1000ULL*1000ULL },
                { "P", 1000ULL*1000ULL*1000ULL*1000ULL*1000ULL },
                { "T", 1000ULL*1000ULL*1000ULL*1000ULL },
                { "G", 1000ULL*1000ULL*1000ULL },
                { "M", 1000ULL*1000ULL },
                { "K", 1000ULL },
                { "B", 1ULL },
                { "",  1ULL },
        };

        const struct table *table;
        const char *p;
        unsigned long long r = 0;
        unsigned n_entries, start_pos = 0;

        assert(t);
        assert(IN_SET(base, 1000, 1024));
        assert(size);

        if (base == 1000) {
                table = si;
                n_entries = ELEMENTSOF(si);
        } else {
                table = iec;
                n_entries = ELEMENTSOF(iec);
        }

        p = t;
        do {
                unsigned long long l, tmp;
                double frac = 0;
                char *e;
                unsigned i;

                p += strspn(p, WHITESPACE);

                errno = 0;
                l = strtoull(p, &e, 10);
                if (errno > 0)
                        return -errno;
                if (e == p)
                        return -EINVAL;
                if (*p == '-')
                        return -ERANGE;

                if (*e == '.') {
                        e++;

                        /* strtoull() itself would accept space/+/- */
                        if (ascii_isdigit(*e)) {
                                unsigned long long l2;
                                char *e2;

                                l2 = strtoull(e, &e2, 10);
                                if (errno > 0)
                                        return -errno;

                                /* Ignore failure. E.g. 10.M is valid */
                                frac = l2;
                                for (; e < e2; e++)
                                        frac /= 10;
                        }
                }

                e += strspn(e, WHITESPACE);

                for (i = start_pos; i < n_entries; i++)
                        if (startswith(e, table[i].suffix))
                                break;

                if (i >= n_entries)
                        return -EINVAL;

                if (l + (frac > 0) > ULLONG_MAX / table[i].factor)
                        return -ERANGE;

                tmp = l * table[i].factor + (unsigned long long) (frac * table[i].factor);
                if (tmp > ULLONG_MAX - r)
                        return -ERANGE;

                r += tmp;
                if ((unsigned long long) (uint64_t) r != r)
                        return -ERANGE;

                p = e + strlen(table[i].suffix);

                start_pos = i + 1;

        } while (*p);

        *size = r;

        return 0;
}

int parse_sector_size(const char *t, uint64_t *ret) {
        int r;

        assert(t);
        assert(ret);

        uint64_t ss;

        r = safe_atou64(t, &ss);
        if (r < 0)
                return log_error_errno(r, "Failed to parse sector size parameter %s", t);
        if (ss < 512 || ss > 4096) /* Allow up to 4K due to dm-crypt support and 4K alignment by the homed LUKS backend */
                return log_error_errno(SYNTHETIC_ERRNO(ERANGE), "Sector size not between 512 and 4096: %s", t);
        if (!ISPOWEROF2(ss))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Sector size not power of 2: %s", t);

        *ret = ss;
        return 0;
}

int parse_range(const char *t, unsigned *lower, unsigned *upper) {
        _cleanup_free_ char *word = NULL;
        unsigned l, u;
        int r;

        assert(lower);
        assert(upper);

        /* Extract the lower bound. */
        r = extract_first_word(&t, &word, "-", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = safe_atou(word, &l);
        if (r < 0)
                return r;

        /* Check for the upper bound and extract it if needed */
        if (!t)
                /* Single number with no dashes. */
                u = l;
        else if (!*t)
                /* Trailing dash is an error. */
                return -EINVAL;
        else {
                r = safe_atou(t, &u);
                if (r < 0)
                        return r;
        }

        *lower = l;
        *upper = u;
        return 0;
}

int parse_errno(const char *t) {
        int r, e;

        assert(t);

        r = errno_from_name(t);
        if (r > 0)
                return r;

        r = safe_atoi(t, &e);
        if (r < 0)
                return r;

        /* 0 is also allowed here */
        if (!errno_is_valid(e) && e != 0)
                return -ERANGE;

        return e;
}

int parse_fd(const char *t) {
        int r, fd;

        assert(t);

        r = safe_atoi(t, &fd);
        if (r < 0)
                return r;

        if (fd < 0)
                return -EBADF;

        return fd;
}

static const char *mangle_base(const char *s, unsigned *base) {
        const char *k;

        assert(s);
        assert(base);

        /* Base already explicitly specified, then don't do anything. */
        if (SAFE_ATO_MASK_FLAGS(*base) != 0)
                return s;

        /* Support Python 3 style "0b" and 0x" prefixes, because they truly make sense, much more than C's "0" prefix for octal. */
        k = STARTSWITH_SET(s, "0b", "0B");
        if (k) {
                *base = 2 | (*base & SAFE_ATO_ALL_FLAGS);
                return k;
        }

        k = STARTSWITH_SET(s, "0o", "0O");
        if (k) {
                *base = 8 | (*base & SAFE_ATO_ALL_FLAGS);
                return k;
        }

        return s;
}

int safe_atou_full(const char *s, unsigned base, unsigned *ret_u) {
        char *x = NULL;
        unsigned long l;

        assert(s);
        assert(SAFE_ATO_MASK_FLAGS(base) <= 16);

        /* strtoul() is happy to parse negative values, and silently converts them to unsigned values without
         * generating an error. We want a clean error, hence let's look for the "-" prefix on our own, and
         * generate an error. But let's do so only after strtoul() validated that the string is clean
         * otherwise, so that we return EINVAL preferably over ERANGE. */

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_WHITESPACE) &&
            strchr(WHITESPACE, s[0]))
                return -EINVAL;

        s += strspn(s, WHITESPACE);

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_PLUS_MINUS) &&
            IN_SET(s[0], '+', '-'))
                return -EINVAL; /* Note that we check the "-" prefix again a second time below, but return a
                                 * different error. I.e. if the SAFE_ATO_REFUSE_PLUS_MINUS flag is set we
                                 * blanket refuse +/- prefixed integers, while if it is missing we'll just
                                 * return ERANGE, because the string actually parses correctly, but doesn't
                                 * fit in the return type. */

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_ZERO) &&
            s[0] == '0' && !streq(s, "0"))
                return -EINVAL; /* This is particularly useful to avoid ambiguities between C's octal
                                 * notation and assumed-to-be-decimal integers with a leading zero. */

        s = mangle_base(s, &base);

        errno = 0;
        l = strtoul(s, &x, SAFE_ATO_MASK_FLAGS(base) /* Let's mask off the flags bits so that only the actual
                                                      * base is left */);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if (l != 0 && s[0] == '-')
                return -ERANGE;
        if ((unsigned long) (unsigned) l != l)
                return -ERANGE;

        if (ret_u)
                *ret_u = (unsigned) l;

        return 0;
}

int safe_atou_bounded(const char *s, unsigned min, unsigned max, unsigned *ret) {
        unsigned v;
        int r;

        r = safe_atou(s, &v);
        if (r < 0)
                return r;

        if (v < min || v > max)
                return -ERANGE;

        *ret = v;
        return 0;
}

int safe_atoi(const char *s, int *ret_i) {
        unsigned base = 0;
        char *x = NULL;
        long l;

        assert(s);

        s += strspn(s, WHITESPACE);
        s = mangle_base(s, &base);

        errno = 0;
        l = strtol(s, &x, base);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if ((long) (int) l != l)
                return -ERANGE;

        if (ret_i)
                *ret_i = (int) l;

        return 0;
}

int safe_atollu_full(const char *s, unsigned base, unsigned long long *ret_llu) {
        char *x = NULL;
        unsigned long long l;

        assert(s);
        assert(SAFE_ATO_MASK_FLAGS(base) <= 16);

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_WHITESPACE) &&
            strchr(WHITESPACE, s[0]))
                return -EINVAL;

        s += strspn(s, WHITESPACE);

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_PLUS_MINUS) &&
            IN_SET(s[0], '+', '-'))
                return -EINVAL;

        if (FLAGS_SET(base, SAFE_ATO_REFUSE_LEADING_ZERO) &&
            s[0] == '0' && s[1] != 0)
                return -EINVAL;

        s = mangle_base(s, &base);

        errno = 0;
        l = strtoull(s, &x, SAFE_ATO_MASK_FLAGS(base));
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if (l != 0 && s[0] == '-')
                return -ERANGE;

        if (ret_llu)
                *ret_llu = l;

        return 0;
}

int safe_atolli(const char *s, long long int *ret_lli) {
        unsigned base = 0;
        char *x = NULL;
        long long l;

        assert(s);

        s += strspn(s, WHITESPACE);
        s = mangle_base(s, &base);

        errno = 0;
        l = strtoll(s, &x, base);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;

        if (ret_lli)
                *ret_lli = l;

        return 0;
}

int safe_atou8_full(const char *s, unsigned base, uint8_t *ret) {
        unsigned u;
        int r;

        r = safe_atou_full(s, base, &u);
        if (r < 0)
                return r;
        if (u > UINT8_MAX)
                return -ERANGE;

        *ret = (uint8_t) u;
        return 0;
}

int safe_atou16_full(const char *s, unsigned base, uint16_t *ret) {
        unsigned u;
        int r;

        r = safe_atou_full(s, base, &u);
        if (r < 0)
                return r;
        if (u > UINT16_MAX)
                return -ERANGE;

        *ret = (uint16_t) u;
        return 0;
}

int safe_atoi16(const char *s, int16_t *ret) {
        unsigned base = 0;
        char *x = NULL;
        long l;

        assert(s);

        s += strspn(s, WHITESPACE);
        s = mangle_base(s, &base);

        errno = 0;
        l = strtol(s, &x, base);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;
        if ((long) (int16_t) l != l)
                return -ERANGE;

        if (ret)
                *ret = (int16_t) l;

        return 0;
}

int safe_atod(const char *s, double *ret_d) {
        _cleanup_(freelocalep) locale_t loc = (locale_t) 0;
        char *x = NULL;
        double d = 0;

        assert(s);

        loc = newlocale(LC_NUMERIC_MASK, "C", (locale_t) 0);
        if (loc == (locale_t) 0)
                return -errno;

        errno = 0;
        d = strtod_l(s, &x, loc);
        if (errno > 0)
                return -errno;
        if (!x || x == s || *x != 0)
                return -EINVAL;

        if (ret_d)
                *ret_d = (double) d;

        return 0;
}

int parse_fractional_part_u(const char **p, size_t digits, unsigned *res) {
        unsigned val = 0;
        const char *s;

        s = *p;

        /* accept any number of digits, strtoull is limited to 19 */
        for (size_t i = 0; i < digits; i++,s++) {
                if (!ascii_isdigit(*s)) {
                        if (i == 0)
                                return -EINVAL;

                        /* too few digits, pad with 0 */
                        for (; i < digits; i++)
                                val *= 10;

                        break;
                }

                val *= 10;
                val += *s - '0';
        }

        /* maybe round up */
        if (*s >= '5' && *s <= '9')
                val++;

        s += strspn(s, DIGITS);

        *p = s;
        *res = val;

        return 0;
}

int parse_nice(const char *p, int *ret) {
        int n, r;

        r = safe_atoi(p, &n);
        if (r < 0)
                return r;

        if (!nice_is_valid(n))
                return -ERANGE;

        *ret = n;
        return 0;
}

int parse_ip_port(const char *s, uint16_t *ret) {
        uint16_t l;
        int r;

        r = safe_atou16_full(s, SAFE_ATO_REFUSE_LEADING_WHITESPACE, &l);
        if (r < 0)
                return r;

        if (l == 0)
                return -EINVAL;

        *ret = (uint16_t) l;

        return 0;
}

int parse_ip_port_range(const char *s, uint16_t *low, uint16_t *high, bool allow_zero) {
        unsigned l, h;
        unsigned min = allow_zero ? -1 : 0;
        int r;

        r = parse_range(s, &l, &h);
        if (r < 0)
                return r;

        if (l <= min || l > 65535 || h <= min || h > 65535)
                return -EINVAL;

        if (h < l)
                return -EINVAL;

        *low = l;
        *high = h;

        return 0;
}

int parse_ip_prefix_length(const char *s, int *ret) {
        unsigned l;
        int r;

        r = safe_atou(s, &l);
        if (r < 0)
                return r;

        if (l > 128)
                return -ERANGE;

        *ret = (int) l;

        return 0;
}

int parse_oom_score_adjust(const char *s, int *ret) {
        int r, v;

        assert(s);
        assert(ret);

        r = safe_atoi(s, &v);
        if (r < 0)
                return r;

        if (!oom_score_adjust_is_valid(v))
                return -ERANGE;

        *ret = v;
        return 0;
}

int store_loadavg_fixed_point(unsigned long i, unsigned long f, loadavg_t *ret) {
        assert(ret);

        if (i >= (~0UL << LOADAVG_PRECISION_BITS))
                return -ERANGE;

        i = i << LOADAVG_PRECISION_BITS;
        f = DIV_ROUND_UP((f << LOADAVG_PRECISION_BITS), 100);

        if (f >= LOADAVG_FIXED_POINT_1_0)
                return -ERANGE;

        *ret = i | f;
        return 0;
}

int parse_loadavg_fixed_point(const char *s, loadavg_t *ret) {
        const char *d, *f_str, *i_str;
        unsigned long i, f;
        int r;

        assert(s);
        assert(ret);

        d = strchr(s, '.');
        if (!d)
                return -EINVAL;

        i_str = strndupa_safe(s, d - s);
        f_str = d + 1;

        r = safe_atolu_full(i_str, 10, &i);
        if (r < 0)
                return r;

        r = safe_atolu_full(f_str, 10, &f);
        if (r < 0)
                return r;

        return store_loadavg_fixed_point(i, f, ret);
}

/* Limitations are described in https://www.netfilter.org/projects/nftables/manpage.html and
 * https://bugzilla.netfilter.org/show_bug.cgi?id=1175 */
bool nft_identifier_valid(const char *id) {
        if (!id)
                return false;

        size_t len = strlen(id);
        if (len == 0 || len > 31)
                return false;

        if (!ascii_isalpha(id[0]))
                return false;

        for (size_t i = 1; i < len; i++)
                if (!ascii_isalpha(id[i]) && !ascii_isdigit(id[i]) && !IN_SET(id[i], '/', '\\', '_', '.'))
                        return false;
        return true;
}
