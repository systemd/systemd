/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/utsname.h>
#include <ctype.h>

#include "util.h"
#include "hostname-util.h"

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

char* gethostname_malloc(void) {
        struct utsname u;

        assert_se(uname(&u) >= 0);

        if (isempty(u.nodename) || streq(u.nodename, "(none)"))
                return strdup(u.sysname);

        return strdup(u.nodename);
}

static bool hostname_valid_char(char c) {
        return
                (c >= 'a' && c <= 'z') ||
                (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') ||
                c == '-' ||
                c == '_' ||
                c == '.';
}

bool hostname_is_valid(const char *s) {
        const char *p;
        bool dot;

        if (isempty(s))
                return false;

        /* Doesn't accept empty hostnames, hostnames with trailing or
         * leading dots, and hostnames with multiple dots in a
         * sequence. Also ensures that the length stays below
         * HOST_NAME_MAX. */

        for (p = s, dot = true; *p; p++) {
                if (*p == '.') {
                        if (dot)
                                return false;

                        dot = true;
                } else {
                        if (!hostname_valid_char(*p))
                                return false;

                        dot = false;
                }
        }

        if (dot)
                return false;

        if (p-s > HOST_NAME_MAX)
                return false;

        return true;
}

char* hostname_cleanup(char *s, bool lowercase) {
        char *p, *d;
        bool dot;

        assert(s);

        for (p = s, d = s, dot = true; *p; p++) {
                if (*p == '.') {
                        if (dot)
                                continue;

                        *(d++) = '.';
                        dot = true;
                } else if (hostname_valid_char(*p)) {
                        *(d++) = lowercase ? tolower(*p) : *p;
                        dot = false;
                }

        }

        if (dot && d > s)
                d[-1] = 0;
        else
                *d = 0;

        strshorten(s, HOST_NAME_MAX);

        return s;
}

bool is_localhost(const char *hostname) {
        assert(hostname);

        /* This tries to identify local host and domain names
         * described in RFC6761 plus the redhatism of .localdomain */

        return streq(hostname, "localhost") ||
               streq(hostname, "localhost.") ||
               streq(hostname, "localdomain.") ||
               streq(hostname, "localdomain") ||
               endswith(hostname, ".localhost") ||
               endswith(hostname, ".localhost.") ||
               endswith(hostname, ".localdomain") ||
               endswith(hostname, ".localdomain.");
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

int read_hostname_config(const char *path, char **hostname) {
        _cleanup_fclose_ FILE *f = NULL;
        char l[LINE_MAX];
        char *name = NULL;

        assert(path);
        assert(hostname);

        f = fopen(path, "re");
        if (!f)
                return -errno;

        /* may have comments, ignore them */
        FOREACH_LINE(l, f, return -errno) {
                truncate_nl(l);
                if (l[0] != '\0' && l[0] != '#') {
                        /* found line with value */
                        name = hostname_cleanup(l, false);
                        name = strdup(name);
                        if (!name)
                                return -ENOMEM;
                        break;
                }
        }

        if (!name)
                /* no non-empty line found */
                return -ENOENT;

        *hostname = name;
        return 0;
}
