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
#include "fileio.h"

static int read_and_strip_hostname(const char *path, char **hn) {
        char *s;
        int r;

        assert(path);
        assert(hn);

        r = read_one_line_file(path, &s);
        if (r < 0)
                return r;

        hostname_cleanup(s, false);

        if (isempty(s)) {
                free(s);
                return -ENOENT;
        }

        *hn = s;
        return 0;
}

int hostname_setup(void) {
        int r;
        _cleanup_free_ char *b = NULL;
        const char *hn;
        bool enoent = false;

        r = read_and_strip_hostname("/etc/hostname", &b);
        if (r < 0) {
                if (r == -ENOENT)
                        enoent = true;
                else
                        log_warning("Failed to read configured hostname: %s", strerror(-r));

                hn = NULL;
        } else
                hn = b;

        if (isempty(hn)) {
                /* Don't override the hostname if it is already set
                 * and not explicitly configured */
                if (hostname_is_set())
                        return 0;

                if (enoent)
                        log_info("No hostname configured.");

                hn = "localhost";
        }

        if (sethostname(hn, strlen(hn)) < 0) {
                log_warning("Failed to set hostname to <%s>: %m", hn);
                return -errno;
        }

        log_info("Set hostname to <%s>.", hn);
        return 0;
}
