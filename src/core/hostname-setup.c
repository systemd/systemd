/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include "hostname-setup.h"
#include "macro.h"
#include "util.h"
#include "log.h"

#if defined(TARGET_ALTLINUX) || defined(TARGET_MANDRIVA) || defined(TARGET_MAGEIA)
#define FILENAME "/etc/sysconfig/network"
#elif defined(TARGET_SUSE) || defined(TARGET_SLACKWARE)
#define FILENAME "/etc/HOSTNAME"
#elif defined(TARGET_GENTOO)
#define FILENAME "/etc/conf.d/hostname"
#endif

static int read_and_strip_hostname(const char *path, char **hn) {
        char *s;
        int r;

        assert(path);
        assert(hn);

        r = read_one_line_file(path, &s);
        if (r < 0)
                return r;

        hostname_cleanup(s);

        if (isempty(s)) {
                free(s);
                return -ENOENT;
        }

        *hn = s;

        return 0;
}

static int read_distro_hostname(char **hn) {

#if defined(TARGET_GENTOO) || defined(TARGET_ALTLINUX) || defined(TARGET_MANDRIVA) || defined(TARGET_MAGEIA)
        int r;
        _cleanup_fclose_ FILE *f = NULL;

        assert(hn);

        f = fopen(FILENAME, "re");
        if (!f)
                return -errno;

        for (;;) {
                char line[LINE_MAX];
                char *s, *k;

                if (!fgets(line, sizeof(line), f)) {
                        if (feof(f))
                                break;

                        r = -errno;
                        goto finish;
                }

                s = strstrip(line);

                if (!startswith_no_case(s, "HOSTNAME="))
                        continue;

                k = strdup(s+9);
                if (!k) {
                        r = -ENOMEM;
                        goto finish;
                }

                hostname_cleanup(k);

                if (isempty(k)) {
                        free(k);
                        r = -ENOENT;
                        goto finish;
                }

                *hn = k;
                r = 0;
                goto finish;
        }

        r = -ENOENT;

finish:
        return r;

#elif defined(TARGET_SUSE) || defined(TARGET_SLACKWARE)
        return read_and_strip_hostname(FILENAME, hn);
#else
        return -ENOENT;
#endif
}

static int read_hostname(char **hn) {
        int r;

        assert(hn);

        /* First, try to load the generic hostname configuration file,
         * that we support on all distributions */

        r = read_and_strip_hostname("/etc/hostname", hn);
        if (r < 0) {
                if (r == -ENOENT)
                        return read_distro_hostname(hn);

                return r;
        }

        return 0;
}

int hostname_setup(void) {
        int r;
        char *b = NULL;
        const char *hn = NULL;
        bool enoent = false;

        r = read_hostname(&b);
        if (r < 0) {
                hn = NULL;

                if (r == -ENOENT)
                        enoent = true;
                else
                        log_warning("Failed to read configured hostname: %s", strerror(-r));
        } else
                hn = b;

        if (isempty(hn)) {
                /* Don't override the hostname if it is already set
                 * and not explicitly configured */
                if (hostname_is_set())
                        goto finish;

                if (enoent)
                        log_info("No hostname configured.");

                hn = "localhost";
        }

        if (sethostname(hn, strlen(hn)) < 0) {
                log_warning("Failed to set hostname to <%s>: %m", hn);
                r = -errno;
        } else
                log_info("Set hostname to <%s>.", hn);

finish:
        free(b);

        return r;
}
