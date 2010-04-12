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
#include "macro.h"
#include "util.h"

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;
} MountPoint;

static const MountPoint mount_table[] = {
        { "proc",    "/proc",             "proc",     NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
        { "sysfs",   "/sys",              "sysfs",    NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
        { "devtmps", "/dev",              "devtmpfs", "mode=755",  MS_NOSUID },
        { "tmpfs",   "/dev/shm",          "tmpfs",    "mode=1777", MS_NOSUID|MS_NOEXEC|MS_NODEV },
        { "devpts",  "/dev/pts",          "devpts",   NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
        { "cgroup",  "/cgroup/debug",     "cgroup",   "debug",     MS_NOSUID|MS_NOEXEC|MS_NODEV },
        { "debugfs", "/sys/kernel/debug", "debugfs",  NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV }
};

bool mount_point_is_api(const char *path) {
        unsigned i;

        /* Checks if this mount point is considered "API", and hence
         * should be ignored */

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if (path_startswith(path, mount_table[i].where))
                        return true;

        return false;
}

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

static int mount_one(const MountPoint *p) {
        int r;

        assert(p);

        if ((r = is_mount_point(p->where)) < 0)
                return r;

        if (r > 0)
                return 0;

        /* The access mode here doesn't really matter too much, since
         * the mounted file system will take precedence anyway. */
        mkdir_p(p->where, 0755);

        log_debug("Mounting %s to %s of type %s with options %s.",
                  p->what,
                  p->where,
                  p->type,
                  strna(p->options));

        if (mount(p->what,
                  p->where,
                  p->type,
                  p->flags,
                  p->options) < 0) {
                log_error("Failed to mount %s: %s", p->where, strerror(errno));
                return -errno;
        }

        return 0;
}

int mount_setup(void) {
        int r;
        unsigned i;

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if ((r = mount_one(mount_table+i)) < 0)
                        return r;

        return 0;
}
