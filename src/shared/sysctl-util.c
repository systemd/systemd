/* SPDX-License-Identifier: LGPL-2.1+ */
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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"
#include "sysctl-util.h"

char *sysctl_normalize(char *s) {
        char *n;

        n = strpbrk(s, "/.");
        /* If the first separator is a slash, the path is
         * assumed to be normalized and slashes remain slashes
         * and dots remains dots. */
        if (!n || *n == '/')
                return s;

        /* Otherwise, dots become slashes and slashes become
         * dots. Fun. */
        while (n) {
                if (*n == '.')
                        *n = '/';
                else
                        *n = '.';

                n = strpbrk(n + 1, "/.");
        }

        return s;
}

int sysctl_write(const char *property, const char *value) {
        char *p;
        _cleanup_close_ int fd = -1;

        assert(property);
        assert(value);

        log_debug("Setting '%s' to '%s'", property, value);

        p = strjoina("/proc/sys/", property);
        fd = open(p, O_WRONLY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (!endswith(value, "\n"))
                value = strjoina(value, "\n");

        if (write(fd, value, strlen(value)) < 0)
                return -errno;

        return 0;
}

int sysctl_read(const char *property, char **content) {
        char *p;

        assert(property);
        assert(content);

        p = strjoina("/proc/sys/", property);
        return read_full_file(p, content, NULL);
}
