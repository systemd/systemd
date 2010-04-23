/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <utmpx.h>
#include <errno.h>
#include <assert.h>
#include <string.h>
#include <sys/utsname.h>

#include "macro.h"
#include "utmp-wtmp.h"

int utmp_get_runlevel(int *runlevel, int *previous) {
        struct utmpx lookup, *found;
        int r;
        const char *e;

        assert(runlevel);

        /* If these values are set in the environment this takes
         * precedence. Presumably, sysvinit does this to work around a
         * race condition that would otherwise exist where we'd always
         * go to disk and hence might read runlevel data that might be
         * very new and does not apply to the current script being
         * executed. */

        if ((e = getenv("RUNLEVEL")) && e[0] > 0) {
                *runlevel = e[0];

                if (previous) {
                        /* $PREVLEVEL seems to be an Upstart thing */

                        if ((e = getenv("PREVLEVEL")) && e[0] > 0)
                                *previous = e[0];
                        else
                                *previous = 0;
                }

                return 0;
        }

        if (utmpxname(_PATH_UTMPX) < 0)
                return -errno;

        setutxent();

        zero(lookup);
        lookup.ut_type = RUN_LVL;

        if (!(found = getutxid(&lookup)))
                r = -errno;
        else {
                int a, b;

                a = found->ut_pid & 0xFF;
                b = (found->ut_pid >> 8) & 0xFF;

                if (a < 0 || b < 0)
                        r = -EIO;
                else {
                        *runlevel = a;

                        if (previous)
                                *previous = b;
                        r = 0;
                }
        }

        endutxent();

        return r;
}

static void init_entry(struct utmpx *store, usec_t timestamp) {
        struct utsname uts;

        assert(store);

        zero(*store);
        zero(uts);

        if (timestamp <= 0)
                timestamp = now(CLOCK_REALTIME);

        store->ut_tv.tv_sec = timestamp / USEC_PER_SEC;
        store->ut_tv.tv_usec = timestamp % USEC_PER_SEC;

        if (uname(&uts) >= 0)
                strncpy(store->ut_host, uts.release, sizeof(store->ut_host));

        strncpy(store->ut_line, "~", sizeof(store->ut_line));  /* or ~~ ? */
        strncpy(store->ut_id, "~~", sizeof(store->ut_id));
}

static int write_entry_utmp(const struct utmpx *store) {
        int r;

        assert(store);

        /* utmp is similar to wtmp, but there is only one entry for
         * each entry type resp. user; i.e. basically a key/value
         * table. */

        if (utmpxname(_PATH_UTMPX) < 0)
                return -errno;

        setutxent();

        if (!pututxline(store))
                r = -errno;
        else
                r = 0;

        endutxent();

        return r;
}

static int write_entry_wtmp(const struct utmpx *store) {
        assert(store);

        /* wtmp is a simple append-only file where each entry is
        simply appended to * the end; i.e. basically a log. */

        errno = 0;
        updwtmpx(_PATH_WTMPX, store);
        return -errno;
}

static int write_entry_both(const struct utmpx *store) {
        int r, s;

        r = write_entry_utmp(store);
        s = write_entry_wtmp(store);

        if (r >= 0)
                r = s;

        /* If utmp/wtmp have been disabled, that's a good thing, hence
         * ignore the errors */
        if (r == -ENOENT)
                r = 0;

        return r;
}

int utmp_put_shutdown(usec_t timestamp) {
        struct utmpx store;

        init_entry(&store, timestamp);

        store.ut_type = RUN_LVL;
        strncpy(store.ut_user, "shutdown", sizeof(store.ut_user));

        return write_entry_both(&store);
}

int utmp_put_reboot(usec_t timestamp) {
        struct utmpx store;

        init_entry(&store, timestamp);

        store.ut_type = BOOT_TIME;
        strncpy(store.ut_user, "reboot", sizeof(store.ut_type));

        return write_entry_both(&store);
}

int utmp_put_runlevel(usec_t timestamp, int runlevel, int previous) {
        struct utmpx store;
        int r;

        assert(runlevel > 0);

        if (previous <= 0) {
                /* Find the old runlevel automatically */

                if ((r = utmp_get_runlevel(&previous, NULL)) < 0) {
                        if (r != -ESRCH)
                                return r;

                        previous = 0;
                }

                if (previous == runlevel)
                        return 0;
        }

        init_entry(&store, timestamp);

        store.ut_type = RUN_LVL;
        store.ut_pid = (runlevel & 0xFF) | ((previous & 0xFF) << 8);
        strncpy(store.ut_user, "runlevel", sizeof(store.ut_user));

        return write_entry_both(&store);
}
