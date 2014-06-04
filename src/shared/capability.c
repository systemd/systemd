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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/types.h>
#include <stdarg.h>
#include <ctype.h>
#include <sys/capability.h>
#include <sys/prctl.h>
#include "grp.h"

#include "macro.h"
#include "util.h"
#include "log.h"
#include "fileio.h"
#include "capability.h"

int have_effective_cap(int value) {
        _cleanup_cap_free_ cap_t cap;
        cap_flag_value_t fv;

        cap = cap_get_proc();
        if (!cap)
                return -errno;

        if (cap_get_flag(cap, value, CAP_EFFECTIVE, &fv) < 0)
                return -errno;
        else
                return fv == CAP_SET;
}

unsigned long cap_last_cap(void) {
        static thread_local unsigned long saved;
        static thread_local bool valid = false;
        unsigned long p;

        if (valid)
                return saved;

        p = (unsigned long) CAP_LAST_CAP;

        if (prctl(PR_CAPBSET_READ, p) < 0) {

                /* Hmm, look downwards, until we find one that
                 * works */
                for (p--; p > 0; p --)
                        if (prctl(PR_CAPBSET_READ, p) >= 0)
                                break;

        } else {

                /* Hmm, look upwards, until we find one that doesn't
                 * work */
                for (;; p++)
                        if (prctl(PR_CAPBSET_READ, p+1) < 0)
                                break;
        }

        saved = p;
        valid = true;

        return p;
}

int capability_bounding_set_drop(uint64_t drop, bool right_now) {
        _cleanup_cap_free_ cap_t after_cap = NULL;
        cap_flag_value_t fv;
        unsigned long i;
        int r;

        /* If we are run as PID 1 we will lack CAP_SETPCAP by default
         * in the effective set (yes, the kernel drops that when
         * executing init!), so get it back temporarily so that we can
         * call PR_CAPBSET_DROP. */

        after_cap = cap_get_proc();
        if (!after_cap)
                return -errno;

        if (cap_get_flag(after_cap, CAP_SETPCAP, CAP_EFFECTIVE, &fv) < 0)
                return -errno;

        if (fv != CAP_SET) {
                _cleanup_cap_free_ cap_t temp_cap = NULL;
                static const cap_value_t v = CAP_SETPCAP;

                temp_cap = cap_dup(after_cap);
                if (!temp_cap) {
                        r = -errno;
                        goto finish;
                }

                if (cap_set_flag(temp_cap, CAP_EFFECTIVE, 1, &v, CAP_SET) < 0) {
                        r = -errno;
                        goto finish;
                }

                if (cap_set_proc(temp_cap) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        for (i = 0; i <= cap_last_cap(); i++) {

                if (drop & ((uint64_t) 1ULL << (uint64_t) i)) {
                        cap_value_t v;

                        /* Drop it from the bounding set */
                        if (prctl(PR_CAPBSET_DROP, i) < 0) {
                                r = -errno;
                                goto finish;
                        }
                        v = (cap_value_t) i;

                        /* Also drop it from the inheritable set, so
                         * that anything we exec() loses the
                         * capability for good. */
                        if (cap_set_flag(after_cap, CAP_INHERITABLE, 1, &v, CAP_CLEAR) < 0) {
                                r = -errno;
                                goto finish;
                        }

                        /* If we shall apply this right now drop it
                         * also from our own capability sets. */
                        if (right_now) {
                                if (cap_set_flag(after_cap, CAP_PERMITTED, 1, &v, CAP_CLEAR) < 0 ||
                                    cap_set_flag(after_cap, CAP_EFFECTIVE, 1, &v, CAP_CLEAR) < 0) {
                                        r = -errno;
                                        goto finish;
                                }
                        }
                }
        }

        r = 0;

finish:
        if (cap_set_proc(after_cap) < 0)
                return -errno;

        return r;
}

static int drop_from_file(const char *fn, uint64_t drop) {
        int r, k;
        uint32_t hi, lo;
        uint64_t current, after;
        char *p;

        r = read_one_line_file(fn, &p);
        if (r < 0)
                return r;

        assert_cc(sizeof(hi) == sizeof(unsigned));
        assert_cc(sizeof(lo) == sizeof(unsigned));

        k = sscanf(p, "%u %u", &lo, &hi);
        free(p);

        if (k != 2)
                return -EIO;

        current = (uint64_t) lo | ((uint64_t) hi << 32ULL);
        after = current & ~drop;

        if (current == after)
                return 0;

        lo = (unsigned) (after & 0xFFFFFFFFULL);
        hi = (unsigned) ((after >> 32ULL) & 0xFFFFFFFFULL);

        if (asprintf(&p, "%u %u", lo, hi) < 0)
                return -ENOMEM;

        r = write_string_file(fn, p);
        free(p);

        return r;
}

int capability_bounding_set_drop_usermode(uint64_t drop) {
        int r;

        r = drop_from_file("/proc/sys/kernel/usermodehelper/inheritable", drop);
        if (r < 0)
                return r;

        r = drop_from_file("/proc/sys/kernel/usermodehelper/bset", drop);
        if (r < 0)
                return r;

        return r;
}

int drop_privileges(uid_t uid, gid_t gid, uint64_t keep_capabilities) {

        _cleanup_cap_free_ cap_t d = NULL;
        int r;

        /* Unfortunately we cannot leave privilege dropping to PID 1
         * here, since we want to run as user but want to keep some
         * capabilities. Since file capabilities have been introduced
         * this cannot be done across exec() anymore, unless our
         * binary has the capability configured in the file system,
         * which we want to avoid. */

        if (setresgid(gid, gid, gid) < 0) {
                log_error("Failed change group ID: %m");
                return -errno;
        }

        if (setgroups(0, NULL) < 0) {
                log_error("Failed to drop auxiliary groups list: %m");
                return -errno;
        }

        if (prctl(PR_SET_KEEPCAPS, 1) < 0) {
                log_error("Failed to enable keep capabilities flag: %m");
                return -errno;
        }

        r = setresuid(uid, uid, uid);
        if (r < 0) {
                log_error("Failed change user ID: %m");
                return -errno;
        }

        if (prctl(PR_SET_KEEPCAPS, 0) < 0) {
                log_error("Failed to disable keep capabilities flag: %m");
                return -errno;
        }

        r = capability_bounding_set_drop(~keep_capabilities, true);
        if (r < 0) {
                log_error("Failed to drop capabilities: %s", strerror(-r));
                return r;
        }

        d = cap_init();
        if (!d)
                return log_oom();

        if (keep_capabilities) {
                cap_value_t bits[sizeof(keep_capabilities)*8];
                unsigned i, j = 0;

                for (i = 0; i < sizeof(keep_capabilities)*8; i++)
                        if (keep_capabilities & (1ULL << i))
                                bits[j++] = i;

                if (cap_set_flag(d, CAP_EFFECTIVE, j, bits, CAP_SET) < 0 ||
                    cap_set_flag(d, CAP_PERMITTED, j, bits, CAP_SET) < 0) {
                        log_error("Failed to enable capabilities bits: %m");
                        return -errno;
                }
        }

        if (cap_set_proc(d) < 0) {
                log_error("Failed to increase capabilities: %m");
                return -errno;
        }

        return 0;
}
