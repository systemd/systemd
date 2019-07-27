/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <utmpx.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "macro.h"
#include "memory-util.h"
#include "path-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"
#include "utmp-wtmp.h"

int utmp_get_runlevel(int *runlevel, int *previous) {
        struct utmpx *found, lookup = { .ut_type = RUN_LVL };
        int r;
        const char *e;

        assert(runlevel);

        /* If these values are set in the environment this takes
         * precedence. Presumably, sysvinit does this to work around a
         * race condition that would otherwise exist where we'd always
         * go to disk and hence might read runlevel data that might be
         * very new and does not apply to the current script being
         * executed. */

        e = getenv("RUNLEVEL");
        if (e && e[0] > 0) {
                *runlevel = e[0];

                if (previous) {
                        /* $PREVLEVEL seems to be an Upstart thing */

                        e = getenv("PREVLEVEL");
                        if (e && e[0] > 0)
                                *previous = e[0];
                        else
                                *previous = 0;
                }

                return 0;
        }

        if (utmpxname(_PATH_UTMPX) < 0)
                return -errno;

        setutxent();

        found = getutxid(&lookup);
        if (!found)
                r = -errno;
        else {
                int a, b;

                a = found->ut_pid & 0xFF;
                b = (found->ut_pid >> 8) & 0xFF;

                *runlevel = a;
                if (previous)
                        *previous = b;

                r = 0;
        }

        endutxent();

        return r;
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
        simply appended to the end; i.e. basically a log. */

        errno = 0;
        updwtmpx(_PATH_WTMPX, store);
        return -errno;
}

static int write_utmp_wtmp(const struct utmpx *store_utmp, const struct utmpx *store_wtmp) {
        int r, s;

        r = write_entry_utmp(store_utmp);
        s = write_entry_wtmp(store_wtmp);

        if (r >= 0)
                r = s;

        /* If utmp/wtmp have been disabled, that's a good thing, hence
         * ignore the errors */
        if (r == -ENOENT)
                r = 0;

        return r;
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
        struct utmpx lookup = {
                .ut_type = INIT_PROCESS /* looks for DEAD_PROCESS, LOGIN_PROCESS, USER_PROCESS, too */
        }, store, store_wtmp, *found;

        assert(id);

        setutxent();

        /* Copy the whole string if it fits, or just the suffix without the terminating NUL. */
        copy_suffix(store.ut_id, sizeof(store.ut_id), id);

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

#define TIMEOUT_MSEC 50

static int write_to_terminal(const char *tty, const char *message) {
        _cleanup_close_ int fd = -1;
        const char *p;
        size_t left;
        usec_t end;

        assert(tty);
        assert(message);

        fd = open(tty, O_WRONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC);
        if (fd < 0 || !isatty(fd))
                return -errno;

        p = message;
        left = strlen(message);

        end = now(CLOCK_MONOTONIC) + TIMEOUT_MSEC*USEC_PER_MSEC;

        while (left > 0) {
                ssize_t n;
                struct pollfd pollfd = {
                        .fd = fd,
                        .events = POLLOUT,
                };
                usec_t t;
                int k;

                t = now(CLOCK_MONOTONIC);

                if (t >= end)
                        return -ETIME;

                k = poll(&pollfd, 1, (end - t) / USEC_PER_MSEC);
                if (k < 0)
                        return -errno;

                if (k == 0)
                        return -ETIME;

                n = write(fd, p, left);
                if (n < 0) {
                        if (errno == EAGAIN)
                                continue;

                        return -errno;
                }

                assert((size_t) n <= left);

                p += n;
                left -= n;
        }

        return 0;
}

int utmp_wall(
        const char *message,
        const char *username,
        const char *origin_tty,
        bool (*match_tty)(const char *tty, void *userdata),
        void *userdata) {

        _cleanup_free_ char *text = NULL, *hn = NULL, *un = NULL, *stdin_tty = NULL;
        char date[FORMAT_TIMESTAMP_MAX];
        struct utmpx *u;
        int r;

        hn = gethostname_malloc();
        if (!hn)
                return -ENOMEM;
        if (!username) {
                un = getlogname_malloc();
                if (!un)
                        return -ENOMEM;
        }

        if (!origin_tty) {
                getttyname_harder(STDIN_FILENO, &stdin_tty);
                origin_tty = stdin_tty;
        }

        if (asprintf(&text,
                     "\a\r\n"
                     "Broadcast message from %s@%s%s%s (%s):\r\n\r\n"
                     "%s\r\n\r\n",
                     un ?: username, hn,
                     origin_tty ? " on " : "", strempty(origin_tty),
                     format_timestamp(date, sizeof(date), now(CLOCK_REALTIME)),
                     message) < 0)
                return -ENOMEM;

        setutxent();

        r = 0;

        while ((u = getutxent())) {
                _cleanup_free_ char *buf = NULL;
                const char *path;
                int q;

                if (u->ut_type != USER_PROCESS || u->ut_user[0] == 0)
                        continue;

                /* this access is fine, because STRLEN("/dev/") << 32 (UT_LINESIZE) */
                if (path_startswith(u->ut_line, "/dev/"))
                        path = u->ut_line;
                else {
                        if (asprintf(&buf, "/dev/%.*s", (int) sizeof(u->ut_line), u->ut_line) < 0)
                                return -ENOMEM;

                        path = buf;
                }

                if (!match_tty || match_tty(path, userdata)) {
                        q = write_to_terminal(path, text);
                        if (q < 0)
                                r = q;
                }
        }

        return r;
}
