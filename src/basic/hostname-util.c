/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "hostname-util.h"
#include "macro.h"
#include "string-util.h"

bool hostname_is_set(void) {
        struct utsname u;

        assert_se(uname(&u) >= 0);

        if (isempty(u.nodename))
                return false;

        /* This is the built-in kernel default host name */
        if (streq(u.nodename, "(none)"))
                return false;

        return true;
}

char *gethostname_malloc(void) {
        struct utsname u;

        /* This call tries to return something useful, either the actual hostname
         * or it makes something up. The only reason it might fail is OOM.
         * It might even return "localhost" if that's set. */

        assert_se(uname(&u) >= 0);

        if (isempty(u.nodename) || streq(u.nodename, "(none)"))
                return strdup(FALLBACK_HOSTNAME);

        return strdup(u.nodename);
}

int gethostname_strict(char **ret) {
        struct utsname u;
        char *k;

        /* This call will rather fail than make up a name. It will not return "localhost" either. */

        assert_se(uname(&u) >= 0);

        if (isempty(u.nodename))
                return -ENXIO;

        if (streq(u.nodename, "(none)"))
                return -ENXIO;

        if (is_localhost(u.nodename))
                return -ENXIO;

        k = strdup(u.nodename);
        if (!k)
                return -ENOMEM;

        *ret = k;
        return 0;
}

bool valid_ldh_char(char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-';
}

/**
 * Check if s looks like a valid host name or FQDN. This does not do
 * full DNS validation, but only checks if the name is composed of
 * allowed characters and the length is not above the maximum allowed
 * by Linux (c.f. dns_name_is_valid()). Trailing dot is allowed if
 * allow_trailing_dot is true and at least two components are present
 * in the name. Note that due to the restricted charset and length
 * this call is substantially more conservative than
 * dns_name_is_valid().
 */
bool hostname_is_valid(const char *s, bool allow_trailing_dot) {
        unsigned n_dots = 0;
        const char *p;
        bool dot, hyphen;

        if (isempty(s))
                return false;

        /* Doesn't accept empty hostnames, hostnames with
         * leading dots, and hostnames with multiple dots in a
         * sequence. Also ensures that the length stays below
         * HOST_NAME_MAX. */

        for (p = s, dot = hyphen = true; *p; p++)
                if (*p == '.') {
                        if (dot || hyphen)
                                return false;

                        dot = true;
                        hyphen = false;
                        n_dots++;

                } else if (*p == '-') {
                        if (dot)
                                return false;

                        dot = false;
                        hyphen = true;

                } else {
                        if (!valid_ldh_char(*p))
                                return false;

                        dot = false;
                        hyphen = false;
                }

        if (dot && (n_dots < 2 || !allow_trailing_dot))
                return false;
        if (hyphen)
                return false;

        if (p - s > HOST_NAME_MAX) /* Note that HOST_NAME_MAX is 64 on
                                    * Linux, but DNS allows domain names
                                    * up to 255 characters */
                return false;

        return true;
}

char *hostname_cleanup(char *s) {
        char *p, *d;
        bool dot, hyphen;

        assert(s);

        for (p = s, d = s, dot = hyphen = true; *p && d - s < HOST_NAME_MAX; p++)
                if (*p == '.') {
                        if (dot || hyphen)
                                continue;

                        *(d++) = '.';
                        dot = true;
                        hyphen = false;

                } else if (*p == '-') {
                        if (dot)
                                continue;

                        *(d++) = '-';
                        dot = false;
                        hyphen = true;

                } else if (valid_ldh_char(*p)) {
                        *(d++) = *p;
                        dot = false;
                        hyphen = false;
                }

        if (d > s && IN_SET(d[-1], '-', '.'))
                /* The dot can occur at most once, but we might have multiple
                 * hyphens, hence the loop */
                d--;
        *d = 0;

        return s;
}

bool is_localhost(const char *hostname) {
        assert(hostname);

        /* This tries to identify local host and domain names
         * described in RFC6761 plus the redhatism of localdomain */

        return strcaseeq(hostname, "localhost") || strcaseeq(hostname, "localhost.") ||
                strcaseeq(hostname, "localhost.localdomain") ||
                strcaseeq(hostname, "localhost.localdomain.") || endswith_no_case(hostname, ".localhost") ||
                endswith_no_case(hostname, ".localhost.") ||
                endswith_no_case(hostname, ".localhost.localdomain") ||
                endswith_no_case(hostname, ".localhost.localdomain.");
}

bool is_gateway_hostname(const char *hostname) {
        assert(hostname);

        /* This tries to identify the valid syntaxes for the our
         * synthetic "gateway" host. */

        return strcaseeq(hostname, "_gateway") || strcaseeq(hostname, "_gateway.")
#if ENABLE_COMPAT_GATEWAY_HOSTNAME
                || strcaseeq(hostname, "gateway") || strcaseeq(hostname, "gateway.")
#endif
                ;
}

int sethostname_idempotent(const char *s) {
        char buf[HOST_NAME_MAX + 1] = {};

        assert(s);

        if (gethostname(buf, sizeof(buf)) < 0)
                return -errno;

        if (streq(buf, s))
                return 0;

        if (sethostname(s, strlen(s)) < 0)
                return -errno;

        return 1;
}

int shorten_overlong(const char *s, char **ret) {
        char *h, *p;

        /* Shorten an overlong name to HOST_NAME_MAX or to the first dot,
         * whatever comes earlier. */

        assert(s);

        h = strdup(s);
        if (!h)
                return -ENOMEM;

        if (hostname_is_valid(h, false)) {
                *ret = h;
                return 0;
        }

        p = strchr(h, '.');
        if (p)
                *p = 0;

        strshorten(h, HOST_NAME_MAX);

        if (!hostname_is_valid(h, false)) {
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
                if (r ==
                    0) /* EOF without any hostname? the file is empty, let's treat that exactly like no file at all: ENOENT */
                        return -ENOENT;

                p = strstrip(line);

                /* File may have empty lines or comments, ignore them */
                if (!IN_SET(*p, '\0', '#')) {
                        char *copy;

                        hostname_cleanup(p); /* normalize the hostname */

                        if (!hostname_is_valid(p, true)) /* check that the hostname we return is valid */
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
