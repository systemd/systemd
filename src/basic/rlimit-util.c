/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "macro.h"
#include "missing_resource.h"
#include "process-util.h"
#include "rlimit-util.h"
#include "string-table.h"
#include "strv.h"
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

        log_debug("Failed at setting rlimit " RLIM_FMT " for resource RLIMIT_%s. Will attempt setting value " RLIM_FMT " instead.", rlim->rlim_max, rlimit_to_string(resource), fixed.rlim_max);

        return RET_NERRNO(setrlimit(resource, &fixed));
}

int setrlimit_closest_all(const struct rlimit *const *rlim, int *which_failed) {
        int r;

        assert(rlim);

        /* On failure returns the limit's index that failed in *which_failed, but only if non-NULL */

        for (int i = 0; i < _RLIMIT_MAX; i++) {
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

        /* setrlimit(2) suggests rlim_t is always 64-bit on Linux. */
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
        _cleanup_free_ char *s = NULL;
        int r;

        assert(rl);
        assert(ret);

        if (rl->rlim_cur >= RLIM_INFINITY && rl->rlim_max >= RLIM_INFINITY)
                r = free_and_strdup(&s, "infinity");
        else if (rl->rlim_cur >= RLIM_INFINITY)
                r = asprintf(&s, "infinity:" RLIM_FMT, rl->rlim_max);
        else if (rl->rlim_max >= RLIM_INFINITY)
                r = asprintf(&s, RLIM_FMT ":infinity", rl->rlim_cur);
        else if (rl->rlim_cur == rl->rlim_max)
                r = asprintf(&s, RLIM_FMT, rl->rlim_cur);
        else
                r = asprintf(&s, RLIM_FMT ":" RLIM_FMT, rl->rlim_cur, rl->rlim_max);
        if (r < 0)
                return -ENOMEM;

        *ret = TAKE_PTR(s);
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
        free_many((void**) rl, _RLIMIT_MAX);
}

int rlimit_copy_all(struct rlimit* target[static _RLIMIT_MAX], struct rlimit* const source[static _RLIMIT_MAX]) {
        struct rlimit* copy[_RLIMIT_MAX] = {};

        assert(target);
        assert(source);

        for (int i = 0; i < _RLIMIT_MAX; i++) {
                if (!source[i])
                        continue;

                copy[i] = newdup(struct rlimit, source[i], 1);
                if (!copy[i]) {
                        rlimit_free_all(copy);
                        return -ENOMEM;
                }
        }

        memcpy(target, copy, sizeof(struct rlimit*) * _RLIMIT_MAX);
        return 0;
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

int rlimit_nofile_safe(void) {
        struct rlimit rl;

        /* Resets RLIMIT_NOFILE's soft limit FD_SETSIZE (i.e. 1024), for compatibility with software still using
         * select() */

        if (getrlimit(RLIMIT_NOFILE, &rl) < 0)
                return log_debug_errno(errno, "Failed to query RLIMIT_NOFILE: %m");

        if (rl.rlim_cur <= FD_SETSIZE)
                return 0;

        /* So we might have inherited a hard limit that's larger than the kernel's maximum limit as stored in
         * /proc/sys/fs/nr_open. If we pass this hard limit unmodified to setrlimit(), we'll get EPERM. To
         * make sure that doesn't happen, let's limit our hard limit to the value from nr_open. */
        rl.rlim_max = MIN(rl.rlim_max, (rlim_t) read_nr_open());
        rl.rlim_cur = MIN((rlim_t) FD_SETSIZE, rl.rlim_max);
        if (setrlimit(RLIMIT_NOFILE, &rl) < 0)
                return log_debug_errno(errno, "Failed to lower RLIMIT_NOFILE's soft limit to " RLIM_FMT ": %m", rl.rlim_cur);

        return 1;
}

int pid_getrlimit(pid_t pid, int resource, struct rlimit *ret) {

        static const char * const prefix_table[_RLIMIT_MAX] = {
                [RLIMIT_CPU]        = "Max cpu time",
                [RLIMIT_FSIZE]      = "Max file size",
                [RLIMIT_DATA]       = "Max data size",
                [RLIMIT_STACK]      = "Max stack size",
                [RLIMIT_CORE]       = "Max core file size",
                [RLIMIT_RSS]        = "Max resident set",
                [RLIMIT_NPROC]      = "Max processes",
                [RLIMIT_NOFILE]     = "Max open files",
                [RLIMIT_MEMLOCK]    = "Max locked memory",
                [RLIMIT_AS]         = "Max address space",
                [RLIMIT_LOCKS]      = "Max file locks",
                [RLIMIT_SIGPENDING] = "Max pending signals",
                [RLIMIT_MSGQUEUE]   = "Max msgqueue size",
                [RLIMIT_NICE]       = "Max nice priority",
                [RLIMIT_RTPRIO]     = "Max realtime priority",
                [RLIMIT_RTTIME]     = "Max realtime timeout",
        };

        int r;

        assert(resource >= 0);
        assert(resource < _RLIMIT_MAX);
        assert(pid >= 0);
        assert(ret);

        if (pid == 0 || pid == getpid_cached())
                return RET_NERRNO(getrlimit(resource, ret));

        r = RET_NERRNO(prlimit(pid, resource, /* new_limit= */ NULL, ret));
        if (!ERRNO_IS_NEG_PRIVILEGE(r))
                return r;

        /* We don't have access? Then try to go via /proc/$PID/limits. Weirdly that's world readable in
         * contrast to querying the data via prlimit() */

        const char *p = procfs_file_alloca(pid, "limits");
        _cleanup_free_ void *limits = NULL;

        r = read_full_virtual_file(p, &limits, NULL);
        if (r < 0)
                return -EPERM; /* propagate original permission error if we can't access the limits file */

        _cleanup_strv_free_ char **l = NULL;
        l = strv_split(limits, "\n");
        if (!l)
                return -ENOMEM;

        STRV_FOREACH(i, strv_skip(l, 1)) {
                _cleanup_free_ char *soft = NULL, *hard = NULL;
                uint64_t sv, hv;
                const char *e;

                e = startswith(*i, prefix_table[resource]);
                if (!e)
                        continue;

                if (*e != ' ')
                        continue;

                e += strspn(e, WHITESPACE);

                size_t n;
                n = strcspn(e, WHITESPACE);
                if (n == 0)
                        continue;

                soft = strndup(e, n);
                if (!soft)
                        return -ENOMEM;

                e += n;
                if (*e != ' ')
                        continue;

                e += strspn(e, WHITESPACE);
                n = strcspn(e, WHITESPACE);
                if (n == 0)
                        continue;

                hard = strndup(e, n);
                if (!hard)
                        return -ENOMEM;

                if (streq(soft, "unlimited"))
                        sv = RLIM_INFINITY;
                else {
                        r = safe_atou64(soft, &sv);
                        if (r < 0)
                                return r;
                }

                if (streq(hard, "unlimited"))
                        hv = RLIM_INFINITY;
                else {
                        r = safe_atou64(hard, &hv);
                        if (r < 0)
                                return r;
                }

                *ret = (struct rlimit) {
                        .rlim_cur = sv,
                        .rlim_max = hv,
                };

                return 0;
        }

        return -ENOTRECOVERABLE;
}
