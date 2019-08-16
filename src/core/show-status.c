/* SPDX-License-Identifier: LGPL-2.1+ */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "io-util.h"
#include "parse-util.h"
#include "show-status.h"
#include "string-table.h"
#include "string-util.h"
#include "terminal-util.h"
#include "util.h"

static const char* const show_status_table[_SHOW_STATUS_MAX] = {
        [SHOW_STATUS_NO]        = "no",
        [SHOW_STATUS_AUTO]      = "auto",
        [SHOW_STATUS_TEMPORARY] = "temporary",
        [SHOW_STATUS_YES]       = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(show_status, ShowStatus, SHOW_STATUS_YES);

int parse_show_status(const char *v, ShowStatus *ret) {
        ShowStatus s;

        assert(ret);

        s = show_status_from_string(v);
        if (s < 0 || s == SHOW_STATUS_TEMPORARY)
                return -EINVAL;

        *ret = s;
        return 0;
}

int status_vprintf(const char *status, ShowStatusFlags flags, const char *format, va_list ap) {
        static const char status_indent[] = "         "; /* "[" STATUS "] " */
        _cleanup_free_ char *s = NULL;
        _cleanup_close_ int fd = -1;
        struct iovec iovec[7] = {};
        int n = 0;
        static bool prev_ephemeral;

        assert(format);

        /* This is independent of logging, as status messages are
         * optional and go exclusively to the console. */

        if (vasprintf(&s, format, ap) < 0)
                return log_oom();

        /* Before you ask: yes, on purpose we open/close the console for each status line we write individually. This
         * is a good strategy to avoid PID 1 getting killed by the kernel's SAK concept (it doesn't fix this entirely,
         * but minimizes the time window the kernel might end up killing PID 1 due to SAK). It also makes things easier
         * for us so that we don't have to recover from hangups and suchlike triggered on the console. */

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        if (FLAGS_SET(flags, SHOW_STATUS_ELLIPSIZE)) {
                char *e;
                size_t emax, sl;
                int c;

                c = fd_columns(fd);
                if (c <= 0)
                        c = 80;

                sl = status ? sizeof(status_indent)-1 : 0;

                emax = c - sl - 1;
                if (emax < 3)
                        emax = 3;

                e = ellipsize(s, emax, 50);
                if (e)
                        free_and_replace(s, e);
        }

        if (prev_ephemeral)
                iovec[n++] = IOVEC_MAKE_STRING(ANSI_REVERSE_LINEFEED "\r" ANSI_ERASE_TO_END_OF_LINE);

        if (status) {
                if (!isempty(status)) {
                        iovec[n++] = IOVEC_MAKE_STRING("[");
                        iovec[n++] = IOVEC_MAKE_STRING(status);
                        iovec[n++] = IOVEC_MAKE_STRING("] ");
                } else
                        iovec[n++] = IOVEC_MAKE_STRING(status_indent);
        }

        iovec[n++] = IOVEC_MAKE_STRING(s);
        iovec[n++] = IOVEC_MAKE_STRING("\n");

        if (prev_ephemeral && !FLAGS_SET(flags, SHOW_STATUS_EPHEMERAL))
                iovec[n++] = IOVEC_MAKE_STRING(ANSI_ERASE_TO_END_OF_LINE);
        prev_ephemeral = FLAGS_SET(flags, SHOW_STATUS_EPHEMERAL) ;

        if (writev(fd, iovec, n) < 0)
                return -errno;

        return 0;
}

int status_printf(const char *status, ShowStatusFlags flags, const char *format, ...) {
        va_list ap;
        int r;

        assert(format);

        va_start(ap, format);
        r = status_vprintf(status, flags, format, ap);
        va_end(ap);

        return r;
}

static const char* const status_unit_format_table[_STATUS_UNIT_FORMAT_MAX] = {
        [STATUS_UNIT_FORMAT_NAME]        = "name",
        [STATUS_UNIT_FORMAT_DESCRIPTION] = "description",
};

DEFINE_STRING_TABLE_LOOKUP(status_unit_format, StatusUnitFormat);
