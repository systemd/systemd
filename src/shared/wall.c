/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <poll.h>
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

#define TIMEOUT_USEC (50 * USEC_PER_MSEC)

static int write_to_terminal(const char *tty, const char *message) {
        _cleanup_close_ int fd = -EBADF;
        const char *p;
        size_t left;
        usec_t end;

        assert(tty);
        assert(message);

        fd = open(tty, O_WRONLY|O_NONBLOCK|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;
        if (!isatty(fd))
                return -ENOTTY;

        p = message;
        left = strlen(message);

        end = usec_add(now(CLOCK_MONOTONIC), TIMEOUT_USEC);

        while (left > 0) {
                ssize_t n;
                usec_t t;
                int k;

                t = now(CLOCK_MONOTONIC);
                if (t >= end)
                        return -ETIME;

                k = fd_wait_for_event(fd, POLLOUT, end - t);
                if (ERRNO_IS_NEG_TRANSIENT(k))
                        continue;
                if (k < 0)
                        return k;
                if (k == 0)
                        return -ETIME;

                n = write(fd, p, left);
                if (n < 0) {
                        if (ERRNO_IS_TRANSIENT(errno))
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
        bool (*match_tty)(const char *tty, bool is_local, void *userdata),
        void *userdata) {

        _cleanup_strv_free_ char **sessions = NULL;
        _cleanup_free_ char *text = NULL, *hn = NULL, *un = NULL, *stdin_tty = NULL;
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
                     "\r\n"
                     "Broadcast message from %s@%s%s%s (%s):\r\n\r\n"
                     "%s\r\n\r\n",
                     un ?: username, hn,
                     origin_tty ? " on " : "", strempty(origin_tty),
                     FORMAT_TIMESTAMP(now(CLOCK_REALTIME)),
                     message) < 0)
                return -ENOMEM;

        r = 0;
        sd_get_sessions(&sessions);
        STRV_FOREACH(s, sessions) {
                _cleanup_free_ char *buf = NULL;
                _cleanup_free_ char *tty = NULL;
                _cleanup_free_ char *rhost = NULL;
                const char *path;
                int q;

                sd_session_get_tty(*s, &tty);

                if (path_startswith(tty, "/dev/"))
                        path = tty;
                else {
                        if (asprintf(&buf, "/dev/%s", tty) < 0)
                                return -ENOMEM;
                        path = buf;
                }

                sd_session_get_remote_host(*s, &rhost);
                bool is_local = rhost == NULL;

                if (!match_tty || match_tty(path, is_local, userdata)) {
                        q = write_to_terminal(path, text);
                        if (q < 0)
                                r = q;
                }
        }

        return r;
}
