/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "proc-cmdline.h"
#include "string-util.h"
#include "util.h"

static int sethostname_idempotent_full(const char *s, bool really) {
        char buf[HOST_NAME_MAX + 1] = {};

        assert(s);

        if (gethostname(buf, sizeof(buf) - 1) < 0)
                return -errno;

        if (streq(buf, s))
                return 0;

        if (really &&
            sethostname(s, strlen(s)) < 0)
                return -errno;

        return 1;
}

int sethostname_idempotent(const char *s) {
        return sethostname_idempotent_full(s, true);
}

int shorten_overlong(const char *s, char **ret) {
        char *h, *p;

        /* Shorten an overlong name to HOST_NAME_MAX or to the first dot,
         * whatever comes earlier. */

        assert(s);

        h = strdup(s);
        if (!h)
                return -ENOMEM;

        if (hostname_is_valid(h, 0)) {
                *ret = h;
                return 0;
        }

        p = strchr(h, '.');
        if (p)
                *p = 0;

        strshorten(h, HOST_NAME_MAX);

        if (!hostname_is_valid(h, 0)) {
                free(h);
                return -EDOM;
        }

        *ret = h;
        return 1;
}

int read_etc_hostname_stream(FILE *f, char **ret) {
        int r;

        assert(f);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *line = NULL;
                char *p;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0) /* EOF without any hostname? the file is empty, let's treat that exactly like no file at all: ENOENT */
                        return -ENOENT;

                p = strstrip(line);

                /* File may have empty lines or comments, ignore them */
                if (!IN_SET(*p, '\0', '#')) {
                        char *copy;

                        hostname_cleanup(p); /* normalize the hostname */

                        if (!hostname_is_valid(p, VALID_HOSTNAME_TRAILING_DOT)) /* check that the hostname we return is valid */
                                return -EBADMSG;

                        copy = strdup(p);
                        if (!copy)
                                return -ENOMEM;

                        *ret = copy;
                        return 0;
                }
        }
}

int read_etc_hostname(const char *path, char **ret) {
        _cleanup_fclose_ FILE *f = NULL;

        assert(ret);

        if (!path)
                path = "/etc/hostname";

        f = fopen(path, "re");
        if (!f)
                return -errno;

        return read_etc_hostname_stream(f, ret);

}

static bool hostname_is_set(void) {
        struct utsname u;

        assert_se(uname(&u) >= 0);

        if (isempty(u.nodename))
                return false;

        /* This is the built-in kernel default hostname */
        if (streq(u.nodename, "(none)"))
                return false;

        return true;
}

int hostname_setup(bool really) {
        _cleanup_free_ char *b = NULL;
        const char *hn = NULL;
        bool enoent = false;
        int r;

        r = proc_cmdline_get_key("systemd.hostname", 0, &b);
        if (r < 0)
                log_warning_errno(r, "Failed to retrieve system hostname from kernel command line, ignoring: %m");
        else if (r > 0) {
                if (hostname_is_valid(b, true))
                        hn = b;
                else  {
                        log_warning("Hostname specified on kernel command line is invalid, ignoring: %s", b);
                        b = mfree(b);
                }
        }

        if (!hn) {
                r = read_etc_hostname(NULL, &b);
                if (r < 0) {
                        if (r == -ENOENT)
                                enoent = true;
                        else
                                log_warning_errno(r, "Failed to read configured hostname: %m");
                } else
                        hn = b;
        }

        if (isempty(hn)) {
                /* Don't override the hostname if it is already set and not explicitly configured */
                if (hostname_is_set())
                        return 0;

                if (enoent)
                        log_info("No hostname configured.");

                hn = FALLBACK_HOSTNAME;
        }

        r = sethostname_idempotent_full(hn, really);
        if (r < 0)
                return log_warning_errno(r, "Failed to set hostname to <%s>: %m", hn);
        if (r == 0)
                log_debug("Hostname was already set to <%s>.", hn);
        else
                log_info("Hostname %s to <%s>.",
                         really ? "set" : "would have been set",
                         hn);

        return r;
}
