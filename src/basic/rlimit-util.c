/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <sys/resource.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "macro.h"
#include "missing.h"
#include "rlimit-util.h"
#include "string-table.h"
#include "time-util.h"

int setrlimit_closest(int resource, const struct rlimit *rlim) {
        struct rlimit highest, fixed;

        assert(rlim);

        if (setrlimit(resource, rlim) >= 0)
                return 0;

        if (errno != EPERM)
                return -errno;

        /* So we failed to set the desired setrlimit, then let's try
         * to get as close as we can */
        if (getrlimit(resource, &highest) < 0)
                return -errno;

        /* If the hard limit is unbounded anyway, then the EPERM had other reasons, let's propagate the original EPERM
         * then */
        if (highest.rlim_max == RLIM_INFINITY)
                return -EPERM;

        fixed = (struct rlimit) {
                .rlim_cur = MIN(rlim->rlim_cur, highest.rlim_max),
                .rlim_max = MIN(rlim->rlim_max, highest.rlim_max),
        };

        /* Shortcut things if we wouldn't change anything. */
        if (fixed.rlim_cur == highest.rlim_cur &&
            fixed.rlim_max == highest.rlim_max)
                return 0;

        if (setrlimit(resource, &fixed) < 0)
                return -errno;

        return 0;
}

int setrlimit_closest_all(const struct rlimit *const *rlim, int *which_failed) {
        int i, r;

        assert(rlim);

        /* On failure returns the limit's index that failed in *which_failed, but only if non-NULL */

        for (i = 0; i < _RLIMIT_MAX; i++) {
                if (!rlim[i])
                        continue;

                r = setrlimit_closest(i, rlim[i]);
                if (r < 0) {
                        if (which_failed)
                                *which_failed = i;

                        return r;
                }
        }

        if (which_failed)
                *which_failed = -1;

        return 0;
}

static int rlimit_parse_u64(const char *val, rlim_t *ret) {
        uint64_t u;
        int r;

        assert(val);
        assert(ret);

        if (streq(val, "infinity")) {
                *ret = RLIM_INFINITY;
                return 0;
        }

        /* setrlimit(2) suggests rlim_t is always 64bit on Linux. */
        assert_cc(sizeof(rlim_t) == sizeof(uint64_t));

        r = safe_atou64(val, &u);
        if (r < 0)
                return r;
        if (u >= (uint64_t) RLIM_INFINITY)
                return -ERANGE;

        *ret = (rlim_t) u;
        return 0;
}

static int rlimit_parse_size(const char *val, rlim_t *ret) {
        uint64_t u;
        int r;

        assert(val);
        assert(ret);

        if (streq(val, "infinity")) {
                *ret = RLIM_INFINITY;
                return 0;
        }

        r = parse_size(val, 1024, &u);
        if (r < 0)
                return r;
        if (u >= (uint64_t) RLIM_INFINITY)
                return -ERANGE;

        *ret = (rlim_t) u;
        return 0;
}

static int rlimit_parse_sec(const char *val, rlim_t *ret) {
        uint64_t u;
        usec_t t;
        int r;

        assert(val);
        assert(ret);

        if (streq(val, "infinity")) {
                *ret = RLIM_INFINITY;
                return 0;
        }

        r = parse_sec(val, &t);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY) {
                *ret = RLIM_INFINITY;
                return 0;
        }

        u = (uint64_t) DIV_ROUND_UP(t, USEC_PER_SEC);
        if (u >= (uint64_t) RLIM_INFINITY)
                return -ERANGE;

        *ret = (rlim_t) u;
        return 0;
}

static int rlimit_parse_usec(const char *val, rlim_t *ret) {
        usec_t t;
        int r;

        assert(val);
        assert(ret);

        if (streq(val, "infinity")) {
                *ret = RLIM_INFINITY;
                return 0;
        }

        r = parse_time(val, &t, 1);
        if (r < 0)
                return r;
        if (t == USEC_INFINITY) {
                *ret = RLIM_INFINITY;
                return 0;
        }

        *ret = (rlim_t) t;
        return 0;
}

static int rlimit_parse_nice(const char *val, rlim_t *ret) {
        uint64_t rl;
        int r;

        /* So, Linux is weird. The range for RLIMIT_NICE is 40..1, mapping to the nice levels -20..19. However, the
         * RLIMIT_NICE limit defaults to 0 by the kernel, i.e. a value that maps to nice level 20, which of course is
         * bogus and does not exist. In order to permit parsing the RLIMIT_NICE of 0 here we hence implement a slight
         * asymmetry: when parsing as positive nice level we permit 0..19. When parsing as negative nice level, we
         * permit -20..0. But when parsing as raw resource limit value then we also allow the special value 0.
         *
         * Yeah, Linux is quality engineering sometimes... */

        if (val[0] == '+') {

                /* Prefixed with "+": Parse as positive user-friendly nice value */
                r = safe_atou64(val + 1, &rl);
                if (r < 0)
                        return r;

                if (rl >= PRIO_MAX)
                        return -ERANGE;

                rl = 20 - rl;

        } else if (val[0] == '-') {

                /* Prefixed with "-": Parse as negative user-friendly nice value */
                r = safe_atou64(val + 1, &rl);
                if (r < 0)
                        return r;

                if (rl > (uint64_t) (-PRIO_MIN))
                        return -ERANGE;

                rl = 20 + rl;
        } else {

                /* Not prefixed: parse as raw resource limit value */
                r = safe_atou64(val, &rl);
                if (r < 0)
                        return r;

                if (rl > (uint64_t) (20 - PRIO_MIN))
                        return -ERANGE;
        }

        *ret = (rlim_t) rl;
        return 0;
}

static int (*const rlimit_parse_table[_RLIMIT_MAX])(const char *val, rlim_t *ret) = {
        [RLIMIT_CPU] = rlimit_parse_sec,
        [RLIMIT_FSIZE] = rlimit_parse_size,
        [RLIMIT_DATA] = rlimit_parse_size,
        [RLIMIT_STACK] = rlimit_parse_size,
        [RLIMIT_CORE] = rlimit_parse_size,
        [RLIMIT_RSS] = rlimit_parse_size,
        [RLIMIT_NOFILE] = rlimit_parse_u64,
        [RLIMIT_AS] = rlimit_parse_size,
        [RLIMIT_NPROC] = rlimit_parse_u64,
        [RLIMIT_MEMLOCK] = rlimit_parse_size,
        [RLIMIT_LOCKS] = rlimit_parse_u64,
        [RLIMIT_SIGPENDING] = rlimit_parse_u64,
        [RLIMIT_MSGQUEUE] = rlimit_parse_size,
        [RLIMIT_NICE] = rlimit_parse_nice,
        [RLIMIT_RTPRIO] = rlimit_parse_u64,
        [RLIMIT_RTTIME] = rlimit_parse_usec,
};

int rlimit_parse_one(int resource, const char *val, rlim_t *ret) {
        assert(val);
        assert(ret);

        if (resource < 0)
                return -EINVAL;
        if (resource >= _RLIMIT_MAX)
                return -EINVAL;

        return rlimit_parse_table[resource](val, ret);
}

int rlimit_parse(int resource, const char *val, struct rlimit *ret) {
        _cleanup_free_ char *hard = NULL, *soft = NULL;
        rlim_t hl, sl;
        int r;

        assert(val);
        assert(ret);

        r = extract_first_word(&val, &soft, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = rlimit_parse_one(resource, soft, &sl);
        if (r < 0)
                return r;

        r = extract_first_word(&val, &hard, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (!isempty(val))
                return -EINVAL;
        if (r == 0)
                hl = sl;
        else {
                r = rlimit_parse_one(resource, hard, &hl);
                if (r < 0)
                        return r;
                if (sl > hl)
                        return -EILSEQ;
        }

        *ret = (struct rlimit) {
                .rlim_cur = sl,
                .rlim_max = hl,
        };

        return 0;
}

int rlimit_format(const struct rlimit *rl, char **ret) {
        char *s = NULL;

        assert(rl);
        assert(ret);

        if (rl->rlim_cur >= RLIM_INFINITY && rl->rlim_max >= RLIM_INFINITY)
                s = strdup("infinity");
        else if (rl->rlim_cur >= RLIM_INFINITY)
                (void) asprintf(&s, "infinity:" RLIM_FMT, rl->rlim_max);
        else if (rl->rlim_max >= RLIM_INFINITY)
                (void) asprintf(&s, RLIM_FMT ":infinity", rl->rlim_cur);
        else if (rl->rlim_cur == rl->rlim_max)
                (void) asprintf(&s, RLIM_FMT, rl->rlim_cur);
        else
                (void) asprintf(&s, RLIM_FMT ":" RLIM_FMT, rl->rlim_cur, rl->rlim_max);

        if (!s)
                return -ENOMEM;

        *ret = s;
        return 0;
}

static const char* const rlimit_table[_RLIMIT_MAX] = {
        [RLIMIT_AS]         = "AS",
        [RLIMIT_CORE]       = "CORE",
        [RLIMIT_CPU]        = "CPU",
        [RLIMIT_DATA]       = "DATA",
        [RLIMIT_FSIZE]      = "FSIZE",
        [RLIMIT_LOCKS]      = "LOCKS",
        [RLIMIT_MEMLOCK]    = "MEMLOCK",
        [RLIMIT_MSGQUEUE]   = "MSGQUEUE",
        [RLIMIT_NICE]       = "NICE",
        [RLIMIT_NOFILE]     = "NOFILE",
        [RLIMIT_NPROC]      = "NPROC",
        [RLIMIT_RSS]        = "RSS",
        [RLIMIT_RTPRIO]     = "RTPRIO",
        [RLIMIT_RTTIME]     = "RTTIME",
        [RLIMIT_SIGPENDING] = "SIGPENDING",
        [RLIMIT_STACK]      = "STACK",
};

DEFINE_STRING_TABLE_LOOKUP(rlimit, int);

int rlimit_from_string_harder(const char *s) {
        const char *suffix;

        /* The official prefix */
        suffix = startswith(s, "RLIMIT_");
        if (suffix)
                return rlimit_from_string(suffix);

        /* Our own unit file setting prefix */
        suffix = startswith(s, "Limit");
        if (suffix)
                return rlimit_from_string(suffix);

        return rlimit_from_string(s);
}

void rlimit_free_all(struct rlimit **rl) {
        int i;

        if (!rl)
                return;

        for (i = 0; i < _RLIMIT_MAX; i++)
                rl[i] = mfree(rl[i]);
}

int rlimit_nofile_bump(int limit) {
        int r;

        /* Bumps the (soft) RLIMIT_NOFILE resource limit as close as possible to the specified limit. If a negative
         * limit is specified, bumps it to the maximum the kernel and the hard resource limit allows. This call should
         * be used by all our programs that might need a lot of fds, and that know how to deal with high fd numbers
         * (i.e. do not use select() — which chokes on fds >= 1024) */

        if (limit < 0)
                limit = read_nr_open();

        if (limit < 3)
                limit = 3;

        r = setrlimit_closest(RLIMIT_NOFILE, &RLIMIT_MAKE_CONST(limit));
        if (r < 0)
                return log_debug_errno(r, "Failed to set RLIMIT_NOFILE: %m");

        return 0;
}
