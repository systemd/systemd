/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utmpx.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "hostname-util.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"
#include "time-util.h"
#include "user-util.h"
#include "utmp-wtmp.h"

int utmp_get_runlevel(int *runlevel, int *previous) {
        _unused_ _cleanup_(utxent_cleanup) bool utmpx = false;
        struct utmpx *found, lookup = { .ut_type = RUN_LVL };
        const char *e;

        assert(runlevel);

        /* If these values are set in the environment this takes
         * precedence. Presumably, sysvinit does this to work around a
         * race condition that would otherwise exist where we'd always
         * go to disk and hence might read runlevel data that might be
         * very new and not apply to the current script being executed. */

        e = getenv("RUNLEVEL");
        if (!isempty(e)) {
                *runlevel = e[0];
                if (previous)
                        *previous = 0;

                return 0;
        }

        if (utmpxname(UTMPX_FILE) < 0)
                return -errno;

        utmpx = utxent_start();

        found = getutxid(&lookup);
        if (!found)
                return -errno;

        *runlevel = found->ut_pid & 0xFF;
        if (previous)
                *previous = (found->ut_pid >> 8) & 0xFF;

        return 0;
}

static void init_timestamp(struct utmpx *store, usec_t t) {
        assert(store);

        if (t <= 0)
                t = now(CLOCK_REALTIME);

        store->ut_tv.tv_sec = t / USEC_PER_SEC;
        store->ut_tv.tv_usec = t % USEC_PER_SEC;
}

static void init_entry(struct utmpx *store, usec_t t) {
        struct utsname uts = {};

        assert(store);

        init_timestamp(store, t);

        if (uname(&uts) >= 0)
                strncpy(store->ut_host, uts.release, sizeof(store->ut_host));

        strncpy(store->ut_line, "~", sizeof(store->ut_line));  /* or ~~ ? */
        strncpy(store->ut_id, "~~", sizeof(store->ut_id));
}

static int write_entry_utmp(const struct utmpx *store) {
        _unused_ _cleanup_(utxent_cleanup) bool utmpx = false;

        assert(store);

        /* utmp is similar to wtmp, but there is only one entry for
         * each entry type resp. user; i.e. basically a key/value
         * table. */

        if (utmpxname(UTMPX_FILE) < 0)
                return -errno;

        utmpx = utxent_start();

        if (pututxline(store))
                return 0;
        if (errno == ENOENT) {
                /* If utmp/wtmp have been disabled, that's a good thing, hence ignore the error. */
                log_debug_errno(errno, "Not writing utmp: %m");
                return 0;
        }
        return -errno;
}

static int write_entry_wtmp(const struct utmpx *store) {
        assert(store);

        /* wtmp is a simple append-only file where each entry is
         * simply appended to the end; i.e. basically a log. */

        errno = 0;
        updwtmpx(_PATH_WTMPX, store);
        if (errno == ENOENT) {
                /* If utmp/wtmp have been disabled, that's a good thing, hence ignore the error. */
                log_debug_errno(errno, "Not writing wtmp: %m");
                return 0;
        }
        if (errno == EROFS) {
                log_warning_errno(errno, "Failed to write wtmp record, ignoring: %m");
                return 0;
        }
        return -errno;
}

static int write_utmp_wtmp(const struct utmpx *store_utmp, const struct utmpx *store_wtmp) {
        int r, s;

        r = write_entry_utmp(store_utmp);
        s = write_entry_wtmp(store_wtmp);
        return r < 0 ? r : s;
}

static int write_entry_both(const struct utmpx *store) {
        return write_utmp_wtmp(store, store);
}

int utmp_put_shutdown(void) {
        struct utmpx store = {};

        init_entry(&store, 0);

        store.ut_type = RUN_LVL;
        strncpy(store.ut_user, "shutdown", sizeof(store.ut_user));

        return write_entry_both(&store);
}

int utmp_put_reboot(usec_t t) {
        struct utmpx store = {};

        init_entry(&store, t);

        store.ut_type = BOOT_TIME;
        strncpy(store.ut_user, "reboot", sizeof(store.ut_user));

        return write_entry_both(&store);
}

static void copy_suffix(char *buf, size_t buf_size, const char *src) {
        size_t l;

        l = strlen(src);
        if (l < buf_size)
                strncpy(buf, src, buf_size);
        else
                memcpy(buf, src + l - buf_size, buf_size);
}

int utmp_put_init_process(const char *id, pid_t pid, pid_t sid, const char *line, int ut_type, const char *user) {
        struct utmpx store = {
                .ut_type = INIT_PROCESS,
                .ut_pid = pid,
                .ut_session = sid,
        };
        int r;

        assert(id);
        assert(ut_type != USER_PROCESS || user);

        init_timestamp(&store, 0);

        /* Copy the whole string if it fits, or just the suffix without the terminating NUL. */
        copy_suffix(store.ut_id, sizeof(store.ut_id), id);

        if (line)
                strncpy_exact(store.ut_line, line, sizeof(store.ut_line));

        r = write_entry_both(&store);
        if (r < 0)
                return r;

        if (IN_SET(ut_type, LOGIN_PROCESS, USER_PROCESS)) {
                store.ut_type = LOGIN_PROCESS;
                r = write_entry_both(&store);
                if (r < 0)
                        return r;
        }

        if (ut_type == USER_PROCESS) {
                store.ut_type = USER_PROCESS;
                strncpy(store.ut_user, user, sizeof(store.ut_user)-1);
                r = write_entry_both(&store);
                if (r < 0)
                        return r;
        }

        return 0;
}

int utmp_put_dead_process(const char *id, pid_t pid, int code, int status) {
        _unused_ _cleanup_(utxent_cleanup) bool utmpx = false;
        struct utmpx lookup = {
                .ut_type = INIT_PROCESS /* looks for DEAD_PROCESS, LOGIN_PROCESS, USER_PROCESS, too */
        }, store, store_wtmp, *found;

        assert(id);

        utmpx = utxent_start();

        /* Copy the whole string if it fits, or just the suffix without the terminating NUL. */
        copy_suffix(lookup.ut_id, sizeof(lookup.ut_id), id);

        found = getutxid(&lookup);
        if (!found)
                return 0;

        if (found->ut_pid != pid)
                return 0;

        memcpy(&store, found, sizeof(store));
        store.ut_type = DEAD_PROCESS;
        store.ut_exit.e_termination = code;
        store.ut_exit.e_exit = status;

        zero(store.ut_user);
        zero(store.ut_host);
        zero(store.ut_tv);

        memcpy(&store_wtmp, &store, sizeof(store_wtmp));
        /* wtmp wants the current time */
        init_timestamp(&store_wtmp, 0);

        return write_utmp_wtmp(&store, &store_wtmp);
}

int utmp_put_runlevel(int runlevel, int previous) {
        struct utmpx store = {};
        int r;

        assert(runlevel > 0);

        if (previous <= 0) {
                /* Find the old runlevel automatically */

                r = utmp_get_runlevel(&previous, NULL);
                if (r < 0) {
                        if (r != -ESRCH)
                                return r;

                        previous = 0;
                }
        }

        if (previous == runlevel)
                return 0;

        init_entry(&store, 0);

        store.ut_type = RUN_LVL;
        store.ut_pid = (runlevel & 0xFF) | ((previous & 0xFF) << 8);
        strncpy(store.ut_user, "runlevel", sizeof(store.ut_user));

        return write_entry_both(&store);
}
