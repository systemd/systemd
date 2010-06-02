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
        bool fatal;
} MountPoint;

static const MountPoint mount_table[] = {
        { "proc",        "/proc",                    "proc",        NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "sysfs",       "/sys",                     "sysfs",       NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "devtmpfs",    "/dev",                     "devtmpfs",    "mode=755",          MS_NOSUID,                    true },
        { "tmpfs",       "/dev/shm",                 "tmpfs",       "mode=1777",         MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "devpts",      "/dev/pts",                 "devpts",      NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, false },
        { "tmpfs",       "/cgroup",                  "tmpfs",       "mode=755",          MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "cgroup",      "/cgroup/systemd",          "cgroup",      "none,name=systemd", MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
};

bool mount_point_is_api(const char *path) {
        unsigned i;

        /* Checks if this mount point is considered "API", and hence
         * should be ignored */

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if (path_startswith(path, mount_table[i].where))
                        return true;

        return path_startswith(path, "/cgroup/");
}

static int mount_one(const MountPoint *p) {
        int r;

        assert(p);

        if ((r = path_is_mount_point(p->where)) < 0)
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
                return p->fatal ? -errno : 0;
        }

        return 0;
}

static int mount_cgroup_controllers(void) {
        int r;
        FILE *f;
        char buf [256];

        /* Mount all available cgroup controllers that are built into the kernel. */

        if (!(f = fopen("/proc/cgroups", "re")))
                return -ENOENT;

        /* Ignore the header line */
        (void) fgets(buf, sizeof(buf), f);

        for (;;) {
                MountPoint p;
                char *controller, *where;

                if (fscanf(f, "%ms %*i %*i %*i", &controller) != 1) {

                        if (feof(f))
                                break;

                        log_error("Failed to parse /proc/cgroups.");
                        r = -EIO;
                        goto finish;
                }

                if (asprintf(&where, "/cgroup/%s", controller) < 0) {
                        free(controller);
                        r = -ENOMEM;
                        goto finish;
                }

                zero(p);
                p.what = "cgroup";
                p.where = where;
                p.type = "cgroup";
                p.options = controller;
                p.flags = MS_NOSUID|MS_NOEXEC|MS_NODEV;
                p.fatal = false;

                r = mount_one(&p);
                free(controller);
                free(where);

                if (r < 0)
                        goto finish;
        }

        r = 0;

finish:
        fclose(f);

        return r;
}

int mount_setup(void) {
        int r;
        unsigned i;

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if ((r = mount_one(mount_table+i)) < 0)
                        return r;

        return mount_cgroup_controllers();
}
