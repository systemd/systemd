/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "fd-util.h"
#include "initreq.h"
#include "io-util.h"
#include "parse-util.h"
#include "strv.h"
#include "sysv-compat.h"

#if HAVE_SYSV_COMPAT
int talk_initctl(char rl) {
        struct init_request request;
        _cleanup_close_ int fd = -1;
        const char *p;
        int r;

        /* Try to switch to the specified SysV runlevel. Returns == 0 if the operation does not apply on this
         * system, and > 0 on success. */

        if (rl == 0)
                return 0;

        FOREACH_STRING(p, "/run/initctl", "/dev/initctl") {
                fd = open(p, O_WRONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (fd >= 0 || errno != ENOENT)
                        break;
        }
        if (fd < 0) {
                if (errno == ENOENT)
                        return 0;

                return log_error_errno(errno, "Failed to open initctl fifo: %m");
        }

        request = (struct init_request) {
                .magic = INIT_MAGIC,
                .sleeptime = 0,
                .cmd = INIT_CMD_RUNLVL,
                .runlevel = rl,
        };

        r = loop_write(fd, &request, sizeof(request), false);
        if (r < 0)
                return log_error_errno(r, "Failed to write to %s: %m", p);

        return 1;
}
#endif

int parse_shutdown_time_spec(const char *t, usec_t *ret) {
        assert(t);
        assert(ret);

        if (streq(t, "now"))
                *ret = 0;
        else if (!strchr(t, ':')) {
                uint64_t u;

                if (safe_atou64(t, &u) < 0)
                        return -EINVAL;

                *ret = now(CLOCK_REALTIME) + USEC_PER_MINUTE * u;
        } else {
                char *e = NULL;
                long hour, minute;
                struct tm tm = {};
                time_t s;
                usec_t n;

                errno = 0;
                hour = strtol(t, &e, 10);
                if (errno > 0 || *e != ':' || hour < 0 || hour > 23)
                        return -EINVAL;

                minute = strtol(e+1, &e, 10);
                if (errno > 0 || *e != 0 || minute < 0 || minute > 59)
                        return -EINVAL;

                n = now(CLOCK_REALTIME);
                s = (time_t) (n / USEC_PER_SEC);

                assert_se(localtime_r(&s, &tm));

                tm.tm_hour = (int) hour;
                tm.tm_min = (int) minute;
                tm.tm_sec = 0;

                s = mktime(&tm);
                assert(s >= 0);

                *ret = (usec_t) s * USEC_PER_SEC;

                while (*ret <= n)
                        *ret += USEC_PER_DAY;
        }

        return 0;
}
