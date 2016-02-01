/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>
#include <sys/resource.h>

#include "alloc-util.h"
#include "extract-word.h"
#include "formats-util.h"
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
        assert_se(getrlimit(resource, &highest) == 0);

        fixed.rlim_cur = MIN(rlim->rlim_cur, highest.rlim_max);
        fixed.rlim_max = MIN(rlim->rlim_max, highest.rlim_max);

        if (setrlimit(resource, &fixed) < 0)
                return -errno;

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
        [RLIMIT_NICE] = rlimit_parse_u64,
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

static const char* const rlimit_table[_RLIMIT_MAX] = {
        [RLIMIT_CPU] = "LimitCPU",
        [RLIMIT_FSIZE] = "LimitFSIZE",
        [RLIMIT_DATA] = "LimitDATA",
        [RLIMIT_STACK] = "LimitSTACK",
        [RLIMIT_CORE] = "LimitCORE",
        [RLIMIT_RSS] = "LimitRSS",
        [RLIMIT_NOFILE] = "LimitNOFILE",
        [RLIMIT_AS] = "LimitAS",
        [RLIMIT_NPROC] = "LimitNPROC",
        [RLIMIT_MEMLOCK] = "LimitMEMLOCK",
        [RLIMIT_LOCKS] = "LimitLOCKS",
        [RLIMIT_SIGPENDING] = "LimitSIGPENDING",
        [RLIMIT_MSGQUEUE] = "LimitMSGQUEUE",
        [RLIMIT_NICE] = "LimitNICE",
        [RLIMIT_RTPRIO] = "LimitRTPRIO",
        [RLIMIT_RTTIME] = "LimitRTTIME"
};

DEFINE_STRING_TABLE_LOOKUP(rlimit, int);
