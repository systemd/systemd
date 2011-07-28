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

#include <sys/mount.h>
#include <errno.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <assert.h>
#include <unistd.h>
#include <ftw.h>

#include "mount-setup.h"
#include "log.h"
#include "macro.h"
#include "util.h"
#include "label.h"

#ifndef TTY_GID
#define TTY_GID 5
#endif

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;
        bool fatal;
} MountPoint;

static const MountPoint mount_table[] = {
        { "proc",     "/proc",                  "proc",     NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "sysfs",    "/sys",                   "sysfs",    NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "devtmpfs", "/dev",                   "devtmpfs", "mode=755",          MS_NOSUID,                    true },
        { "tmpfs",    "/dev/shm",               "tmpfs",    "mode=1777",         MS_NOSUID|MS_NODEV,           true },
        { "devpts",   "/dev/pts",               "devpts",   "mode=620,gid=" STRINGIFY(TTY_GID), MS_NOSUID|MS_NOEXEC, false },
        { "tmpfs",    "/run",                   "tmpfs",    "mode=755",          MS_NOSUID|MS_NODEV, true },
        { "tmpfs",    "/sys/fs/cgroup",         "tmpfs",    "mode=755",          MS_NOSUID|MS_NOEXEC|MS_NODEV, false },
        { "cgroup",   "/sys/fs/cgroup/systemd", "cgroup",   "none,name=systemd", MS_NOSUID|MS_NOEXEC|MS_NODEV, false },
};

/* These are API file systems that might be mounted by other software,
 * we just list them here so that we know that we should ignore them */

static const char * const ignore_paths[] = {
        "/sys/fs/selinux",
        "/selinux",
        "/proc/bus/usb"
};

bool mount_point_is_api(const char *path) {
        unsigned i;

        /* Checks if this mount point is considered "API", and hence
         * should be ignored */

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if (path_equal(path, mount_table[i].where))
                        return true;

        return path_startswith(path, "/sys/fs/cgroup/");
}

bool mount_point_ignore(const char *path) {
        unsigned i;

        for (i = 0; i < ELEMENTSOF(ignore_paths); i++)
                if (path_equal(path, ignore_paths[i]))
                        return true;

        return false;
}

static int mount_one(const MountPoint *p) {
        int r;

        assert(p);

        /* Relabel first, just in case */
        label_fix(p->where, true);

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

        /* Relabel again, since we now mounted something fresh here */
        label_fix(p->where, false);

        return 0;
}

static int mount_cgroup_controllers(void) {
        int r;
        FILE *f;
        char buf[LINE_MAX];

        /* Mount all available cgroup controllers that are built into the kernel. */

        if (!(f = fopen("/proc/cgroups", "re"))) {
                log_error("Failed to enumerate cgroup controllers: %m");
                return 0;
        }

        /* Ignore the header line */
        (void) fgets(buf, sizeof(buf), f);

        for (;;) {
                MountPoint p;
                char *controller, *where;
                int enabled = false;

                if (fscanf(f, "%ms %*i %*i %i", &controller, &enabled) != 2) {

                        if (feof(f))
                                break;

                        log_error("Failed to parse /proc/cgroups.");
                        r = -EIO;
                        goto finish;
                }

                if (!enabled) {
                        free(controller);
                        continue;
                }

                if (asprintf(&where, "/sys/fs/cgroup/%s", controller) < 0) {
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

static int symlink_and_label(const char *old_path, const char *new_path) {
        int r;

        assert(old_path);
        assert(new_path);

        if ((r = label_symlinkfile_set(new_path)) < 0)
                return r;

        if (symlink(old_path, new_path) < 0)
                r = -errno;

        label_file_clear();

        return r;
}

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        /* No need to label /dev twice in a row... */
        if (ftwbuf->level == 0)
                return 0;

        label_fix(fpath, true);
        return 0;
};

int mount_setup(bool loaded_policy) {

        const char symlinks[] =
                "/proc/kcore\0"      "/dev/core\0"
                "/proc/self/fd\0"    "/dev/fd\0"
                "/proc/self/fd/0\0"  "/dev/stdin\0"
                "/proc/self/fd/1\0"  "/dev/stdout\0"
                "/proc/self/fd/2\0"  "/dev/stderr\0";

        int r;
        unsigned i;
        const char *j, *k;

        for (i = 0; i < ELEMENTSOF(mount_table); i ++)
                if ((r = mount_one(mount_table+i)) < 0)
                        return r;

        /* Nodes in devtmpfs and /run need to be manually updated for
         * the appropriate labels, after mounting. The other virtual
         * API file systems like /sys and /proc do not need that, they
         * use the same label for all their files. */
        if (loaded_policy) {
                usec_t before_relabel, after_relabel;
                char timespan[FORMAT_TIMESPAN_MAX];

                before_relabel = now(CLOCK_MONOTONIC);

                nftw("/dev", nftw_cb, 64, FTW_MOUNT|FTW_PHYS);
                nftw("/run", nftw_cb, 64, FTW_MOUNT|FTW_PHYS);

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabelled /dev and /run in %s.",
                         format_timespan(timespan, sizeof(timespan), after_relabel - before_relabel));

        }

        /* Create a few default symlinks, which are normally created
         * by udevd, but some scripts might need them before we start
         * udevd. */
        NULSTR_FOREACH_PAIR(j, k, symlinks)
                symlink_and_label(j, k);

        /* Create a few directories we always want around */
        mkdir("/run/systemd", 0755);
        mkdir("/run/systemd/system", 0755);

        return mount_cgroup_controllers();
}
