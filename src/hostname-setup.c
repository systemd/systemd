/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
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

#if defined(TARGET_FEDORA)
#define FILENAME "/etc/sysconfig/network"
#elif defined(TARGET_SUSE) || defined(TARGET_SLACKWARE)
#define FILENAME "/etc/HOSTNAME"
#elif defined(TARGET_ARCH)
#define FILENAME "/etc/rc.conf"
#elif defined(TARGET_GENTOO)
#define FILENAME "/etc/conf.d/hostname"
#endif

static char* strip_bad_chars(char *s) {
        char *p, *d;

        for (p = s, d = s; *p; p++)
                if ((*p >= 'a' && *p <= 'z') ||
                    (*p >= 'A' && *p <= 'Z') ||
                    (*p >= '0' && *p <= '9') ||
                    *p == '-' ||
                    *p == '_' ||
                    *p == '.')
                        *(d++) = *p;

        *d = 0;

        return s;
}

static int read_and_strip_hostname(const char *path, char **hn) {
        char *s, *k;
        int r;

        assert(path);
        assert(hn);

        if ((r = read_one_line_file(path, &s)) < 0)
                return r;

        k = strdup(strstrip(s));
        free(s);

        if (!k)
                return -ENOMEM;

        strip_bad_chars(k);

        if (k[0] == 0) {
                free(k);
                return -ENOENT;
        }

        *hn = k;

        return 0;
}

static int read_distro_hostname(char **hn) {

#if defined(TARGET_FEDORA) || defined(TARGET_ARCH) || defined(TARGET_GENTOO)
        int r;
        FILE *f;

        assert(hn);

        if (!(f = fopen(FILENAME, "re")))
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

                if (!(k = strdup(s+9))) {
                        r = -ENOMEM;
                        goto finish;
                }

                strip_bad_chars(k);

                if (k[0] == 0) {
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
        fclose(f);
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

        if ((r = read_and_strip_hostname("/etc/hostname", hn)) < 0) {

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

        if ((r = read_hostname(&b)) < 0) {
                if (r == -ENOENT)
                        log_info("No hostname configured.");
                else
                        log_warning("Failed to read configured hostname: %s", strerror(-r));

                hn = "localhost";
        } else
                hn = b;

        if (sethostname(hn, strlen(hn)) < 0) {
                log_warning("Failed to set hostname to <%s>: %m", hn);
                r = -errno;
        } else
                log_info("Set hostname to <%s>.", hn);

        free(b);

        return r;
}
