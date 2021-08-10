/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "log.h"
#include "macro.h"
#include "proc-cmdline.h"
#include "string-table.h"
#include "string-util.h"
#include "util.h"

static int sethostname_idempotent_full(const char *s, bool really) {
        char buf[HOST_NAME_MAX + 1];

        assert(s);

        if (gethostname(buf, sizeof(buf)) < 0)
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

bool get_hostname_filtered(char ret[static HOST_NAME_MAX + 1]) {
        char buf[HOST_NAME_MAX + 1];

        /* Returns true if we got a good hostname, false otherwise. */

        if (gethostname(buf, sizeof(buf)) < 0)
                return false;  /* This can realistically only fail with ENAMETOOLONG.
                                * Let's treat that case the same as an invalid hostname. */

        if (isempty(buf))
                return false;

        /* This is the built-in kernel default hostname */
        if (streq(buf, "(none)"))
                return false;

        memcpy(ret, buf, sizeof buf);
        return true;
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

void hostname_update_source_hint(const char *hostname, HostnameSource source) {
        int r;

        /* Why save the value and not just create a flag file? This way we will
         * notice if somebody sets the hostname directly (not going through hostnamed).
         */

        if (source == HOSTNAME_DEFAULT) {
                r = write_string_file("/run/systemd/default-hostname", hostname,
                                      WRITE_STRING_FILE_CREATE | WRITE_STRING_FILE_ATOMIC);
                if (r < 0)
                        log_warning_errno(r, "Failed to create \"/run/systemd/default-hostname\": %m");
        } else
                unlink_or_warn("/run/systemd/default-hostname");
}

int hostname_setup(bool really) {
        _cleanup_free_ char *b = NULL;
        const char *hn = NULL;
        HostnameSource source;
        bool enoent = false;
        int r;

        r = proc_cmdline_get_key("systemd.hostname", 0, &b);
        if (r < 0)
                log_warning_errno(r, "Failed to retrieve system hostname from kernel command line, ignoring: %m");
        else if (r > 0) {
                if (hostname_is_valid(b, true)) {
                        hn = b;
                        source = HOSTNAME_TRANSIENT;
                } else  {
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
                } else {
                        hn = b;
                        source = HOSTNAME_STATIC;
                }
        }

        if (!hn) {
                /* Don't override the hostname if it is already set and not explicitly configured */

                char buf[HOST_NAME_MAX + 1] = {};
                if (get_hostname_filtered(buf)) {
                        log_debug("No hostname configured, leaving existing hostname <%s> in place.", buf);
                        return 0;
                }

                if (enoent)
                        log_info("No hostname configured, using default hostname.");

                hn = b = get_default_hostname();
                if (!hn)
                        return log_oom();

                source = HOSTNAME_DEFAULT;

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

        if (really)
                hostname_update_source_hint(hn, source);

        return r;
}

static const char* const hostname_source_table[] = {
        [HOSTNAME_STATIC]    = "static",
        [HOSTNAME_TRANSIENT] = "transient",
        [HOSTNAME_DEFAULT]   = "default",
};

DEFINE_STRING_TABLE_LOOKUP(hostname_source, HostnameSource);
