/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "alloc-util.h"
#include "hostname-util.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"

char* get_default_hostname(void) {
        int r;

        const char *e = secure_getenv("SYSTEMD_DEFAULT_HOSTNAME");
        if (e) {
                if (hostname_is_valid(e, 0))
                        return strdup(e);
                log_debug("Invalid hostname in $SYSTEMD_DEFAULT_HOSTNAME, ignoring: %s", e);
        }

        _cleanup_free_ char *f = NULL;
        r = parse_os_release(NULL, "DEFAULT_HOSTNAME", &f);
        if (r < 0)
                log_debug_errno(r, "Failed to parse os-release, ignoring: %m");
        else if (f) {
                if (hostname_is_valid(f, 0))
                        return TAKE_PTR(f);
                log_debug("Invalid hostname in os-release, ignoring: %s", f);
        }

        return strdup(FALLBACK_HOSTNAME);
}

char* gethostname_malloc(void) {
        struct utsname u;
        const char *s;

        /* This call tries to return something useful, either the actual hostname
         * or it makes something up. The only reason it might fail is OOM.
         * It might even return "localhost" if that's set. */

        assert_se(uname(&u) >= 0);

        s = u.nodename;
        if (isempty(s) || streq(s, "(none)"))
                return get_default_hostname();

        return strdup(s);
}

char* gethostname_short_malloc(void) {
        struct utsname u;
        const char *s;
        _cleanup_free_ char *f = NULL;

        /* Like above, but kills the FQDN part if present. */

        assert_se(uname(&u) >= 0);

        s = u.nodename;
        if (isempty(s) || streq(s, "(none)") || s[0] == '.') {
                s = f = get_default_hostname();
                if (!s)
                        return NULL;

                assert(s[0] != '.');
        }

        return strndup(s, strcspn(s, "."));
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
        /* "LDH" → "Letters, digits, hyphens", as per RFC 5890, Section 2.3.1 */

        return
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '-';
}

bool hostname_is_valid(const char *s, ValidHostnameFlags flags) {
        unsigned n_dots = 0;
        const char *p;
        bool dot, hyphen;

        /* Check if s looks like a valid hostname or FQDN. This does not do full DNS validation, but only
         * checks if the name is composed of allowed characters and the length is not above the maximum
         * allowed by Linux (c.f. dns_name_is_valid()). A trailing dot is allowed if
         * VALID_HOSTNAME_TRAILING_DOT flag is set and at least two components are present in the name. Note
         * that due to the restricted charset and length this call is substantially more conservative than
         * dns_name_is_valid(). Doesn't accept empty hostnames, hostnames with leading dots, and hostnames
         * with multiple dots in a sequence. Doesn't allow hyphens at the beginning or end of label. */

        if (isempty(s))
                return false;

        if (streq(s, ".host")) /* Used by the container logic to denote the "root container" */
                return FLAGS_SET(flags, VALID_HOSTNAME_DOT_HOST);

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

        if (dot && (n_dots < 2 || !FLAGS_SET(flags, VALID_HOSTNAME_TRAILING_DOT)))
                return false;
        if (hyphen)
                return false;

        if (p-s > HOST_NAME_MAX) /* Note that HOST_NAME_MAX is 64 on Linux, but DNS allows domain names up to
                                  * 255 characters */
                return false;

        return true;
}

char* hostname_cleanup(char *s) {
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

        return STRCASE_IN_SET(
                        hostname,
                        "localhost",
                        "localhost.",
                        "localhost.localdomain",
                        "localhost.localdomain.") ||
                endswith_no_case(hostname, ".localhost") ||
                endswith_no_case(hostname, ".localhost.") ||
                endswith_no_case(hostname, ".localhost.localdomain") ||
                endswith_no_case(hostname, ".localhost.localdomain.");
}
