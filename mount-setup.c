/*-*- Mode: C; c-basic-offset: 8 -*-*/

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

#include <sys/mount.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>

#include "mount-setup.h"
#include "log.h"

enum {
        MOUNT_WHAT,
        MOUNT_WHERE,
        MOUNT_TYPE,
        MOUNT_OPTIONS,
        MOUNT_SKIP
};

static const char *table[] = {
        "/proc",  "/proc",         "proc",   "rw",
        "/sys",   "/sys",          "sysfs",  "rw",
        "cgroup", "/cgroup/debug", "cgroup", "debug",
        NULL
};

static int is_mount_point(const char *t) {
        struct stat a, b;
        char *copy;

        if (lstat(t, &a) < 0) {

                if (errno == ENOENT)
                        return 0;

                return -errno;
        }

        if (!(copy = strdup(t)))
                return -ENOMEM;

        if (lstat(dirname(copy), &b) < 0) {
                free(copy);
                return -errno;
        }

        free(copy);

        return a.st_dev != b.st_dev;

}

static int mount_one(const char *t[]) {
        int r;

        assert(t);

        if ((r = is_mount_point(t[MOUNT_WHERE])) < 0)
                return r;

        if (r > 0)
                return 0;

        log_debug("Mounting %s to %s of type %s with options %s.",
                  t[MOUNT_WHAT],
                  t[MOUNT_WHERE],
                  t[MOUNT_TYPE],
                  t[MOUNT_OPTIONS]);

        if (mount(t[MOUNT_WHAT],
                  t[MOUNT_WHERE],
                  t[MOUNT_TYPE],
                  0,
                  t[MOUNT_OPTIONS]) < 0) {
                log_error("Failed to mount %s: %s", t[MOUNT_WHERE], strerror(errno));
                return -errno;
        }

        return 0;
}

int mount_setup(void) {
        int r;
        const char **t;

        for (t = table; *t; t += MOUNT_SKIP)
                if ((r = mount_one(t)) < 0)
                        return r;

        return 0;
}
