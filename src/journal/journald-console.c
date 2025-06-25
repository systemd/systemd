/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/socket.h>
#include <time.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "iovec-util.h"
#include "journald-console.h"
#include "journald-manager.h"
#include "log.h"
#include "parse-util.h"
#include "process-util.h"
#include "stdio-util.h"
#include "terminal-util.h"
#include "time-util.h"

static bool prefix_timestamp(void) {

        static int cached_printk_time = -1;

        if (_unlikely_(cached_printk_time < 0)) {
                _cleanup_free_ char *p = NULL;

                cached_printk_time =
                        read_one_line_file("/sys/module/printk/parameters/time", &p) >= 0
                        && parse_boolean(p) > 0;
        }

        return cached_printk_time;
}

void manager_forward_console(
                Manager *m,
                int priority,
                const char *identifier,
                const char *message,
                const struct ucred *ucred) {

        struct iovec iovec[7];
        struct timespec ts;
        char tbuf[STRLEN("[] ") + DECIMAL_STR_MAX(ts.tv_sec) + DECIMAL_STR_MAX(ts.tv_nsec)-3 + 1];
        char header_pid[STRLEN("[]: ") + DECIMAL_STR_MAX(pid_t)];
        _cleanup_free_ char *ident_buf = NULL;
        _cleanup_close_ int fd = -EBADF;
        const char *tty, *color_on = "", *color_off = "";
        int n = 0;

        assert(m);
        assert(message);

        if (LOG_PRI(priority) > m->max_level_console)
                return;

        /* First: timestamp */
        if (prefix_timestamp()) {
                assert_se(clock_gettime(CLOCK_MONOTONIC, &ts) == 0);
                xsprintf(tbuf, "[%5"PRI_TIME".%06"PRI_NSEC"] ",
                         ts.tv_sec,
                         (nsec_t)ts.tv_nsec / 1000);

                iovec[n++] = IOVEC_MAKE_STRING(tbuf);
        }

        /* Second: identifier and PID */
        if (ucred) {
                if (!identifier) {
                        (void) pid_get_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                xsprintf(header_pid, "["PID_FMT"]: ", ucred->pid);

                if (identifier)
                        iovec[n++] = IOVEC_MAKE_STRING(identifier);

                iovec[n++] = IOVEC_MAKE_STRING(header_pid);
        } else if (identifier) {
                iovec[n++] = IOVEC_MAKE_STRING(identifier);
                iovec[n++] = IOVEC_MAKE_STRING(": ");
        }

        get_log_colors(LOG_PRI(priority), &color_on, &color_off, NULL);

        /* Fourth: message */
        iovec[n++] = IOVEC_MAKE_STRING(color_on);
        iovec[n++] = IOVEC_MAKE_STRING(message);
        iovec[n++] = IOVEC_MAKE_STRING(color_off);
        iovec[n++] = IOVEC_MAKE_STRING("\n");

        tty = m->tty_path ?: "/dev/console";

        /* Before you ask: yes, on purpose we open/close the console for each log line we write individually. This is a
         * good strategy to avoid journald getting killed by the kernel's SAK concept (it doesn't fix this entirely,
         * but minimizes the time window the kernel might end up killing journald due to SAK). It also makes things
         * easier for us so that we don't have to recover from hangups and suchlike triggered on the console. */

        fd = open_terminal(tty, O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0) {
                log_debug_errno(fd, "Failed to open %s for logging: %m", tty);
                return;
        }

        if (writev(fd, iovec, n) < 0)
                log_debug_errno(errno, "Failed to write to %s for logging: %m", tty);
}
