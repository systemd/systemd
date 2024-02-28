/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <string.h>
#include <unistd.h>

#include "sd-login.h"

#include "errno-util.h"
#include "fd-util.h"
#include "hostname-util.h"
#include "io-util.h"
#include "path-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "user-util.h"
#include "utmp-wtmp.h"
#include "wall.h"

#if ENABLE_UTMP || ENABLE_LOGIND

#define TIMEOUT_USEC (50 * USEC_PER_MSEC)

static int write_to_terminal(const char *tty, const char *message) {
        _cleanup_close_ int fd = -EBADF;

        assert(tty);
        assert(message);

        fd = open(tty, O_WRONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!isatty_safe(fd))
                return -errno;

        return loop_write_full(fd, message, SIZE_MAX, TIMEOUT_USEC);
}

static int wall_utmp(
        const char *message,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata) {

#if ENABLE_UTMP
        _unused_ _cleanup_(utxent_cleanup) bool utmpx = false;
        struct utmpx *u;
        int r = 0;

        assert(message);

        /* libc's setutxent() unfortunately doesn't inform us about success, i.e. whether /var/run/utmp
         * exists. Hence we have to check manually first. */
        if (access(_PATH_UTMPX, F_OK) < 0) {
                if (errno == ENOENT)
                        return -ENOPROTOOPT;

                return -errno;
        }

        utmpx = utxent_start();

        while ((u = getutxent())) {
                _cleanup_free_ char *p = NULL;
                const char *tty_path;
                bool is_local;

                if (u->ut_type != USER_PROCESS || isempty(u->ut_user))
                        continue;

                /* This access is fine, because strlen("/dev/") < 32 (UT_LINESIZE) */
                if (path_startswith(u->ut_line, "/dev/"))
                        tty_path = u->ut_line;
                else {
                        if (asprintf(&p, "/dev/%.*s", (int) sizeof(u->ut_line), u->ut_line) < 0)
                                return -ENOMEM;

                        tty_path = p;
                }

                /* It seems that the address field is always set for remote logins. For local logins and
                 * other local entries, we get [0,0,0,0]. */
                is_local = eqzero(u->ut_addr_v6);

                if (!match_tty || match_tty(tty_path, is_local, userdata))
                        RET_GATHER(r, write_to_terminal(tty_path, message));
        }

        return r;

#else
        return -ENOPROTOOPT;
#endif
}

static int wall_logind(
        const char *message,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata) {

#if ENABLE_LOGIND
        _cleanup_strv_free_ char **sessions = NULL;
        int r;

        assert(message);

        r = sd_get_sessions(&sessions);
        if (r <= 0)
                return r;

        r = 0;

        STRV_FOREACH(s, sessions) {
                _cleanup_free_ char *tty_path = NULL, *tty = NULL, *rhost = NULL;
                bool is_local;
                int q;

                q = sd_session_get_tty(*s, &tty);
                if (IN_SET(q, -ENXIO, -ENODATA))
                        continue;
                if (q < 0)
                        return RET_GATHER(r, q);

                tty_path = strjoin("/dev/", tty);
                if (!tty_path)
                        return -ENOMEM;

                (void) sd_session_get_remote_host(*s, &rhost);
                is_local = !rhost;

                if (!match_tty || match_tty(tty_path, is_local, userdata))
                        RET_GATHER(r, write_to_terminal(tty_path, message));
        }

        return r;

#else
        return -ENOPROTOOPT;
#endif
}

int wall(
        const char *message,
        const char *username,
        const char *origin_tty,
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata) {

        _cleanup_free_ char *text = NULL, *hostname = NULL, *username_alloc = NULL, *stdin_tty = NULL;
        int r;

        assert(message);

        hostname = gethostname_malloc();
        if (!hostname)
                return -ENOMEM;

        if (!username) {
                username_alloc = getlogname_malloc();
                if (!username_alloc)
                        return -ENOMEM;

                username = username_alloc;
        }

        if (!origin_tty) {
                (void) getttyname_harder(STDIN_FILENO, &stdin_tty);
                origin_tty = stdin_tty;
        }

        if (asprintf(&text,
                     "\r\n"
                     "Broadcast message from %s@%s%s%s (%s):\r\n\r\n"
                     "%s\r\n\r\n",
                     username, hostname,
                     origin_tty ? " on " : "", strempty(origin_tty),
                     FORMAT_TIMESTAMP(now(CLOCK_REALTIME)),
                     message) < 0)
                return -ENOMEM;

        r = wall_utmp(text, match_tty, userdata);
        if (r == -ENOPROTOOPT)
                r = wall_logind(text, match_tty, userdata);

        return r == -ENOPROTOOPT ? 0 : r;
}

#endif
