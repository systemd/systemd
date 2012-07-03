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
#include "dev-setup.h"
#include "log.h"
#include "macro.h"
#include "util.h"
#include "label.h"
#include "set.h"
#include "strv.h"
#include "mkdir.h"
#include "path-util.h"
#include "missing.h"

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

/* The first three entries we might need before SELinux is up. The
 * fourth (securityfs) is needed by IMA to load a custom policy. The
 * other ones we can delay until SELinux and IMA are loaded. */
#define N_EARLY_MOUNT 4

static const MountPoint mount_table[] = {
        { "proc",     "/proc",                  "proc",     NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "sysfs",    "/sys",                   "sysfs",    NULL,                MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
        { "devtmpfs", "/dev",                   "devtmpfs", "mode=755",          MS_NOSUID|MS_STRICTATIME,     true },
        { "securityfs", "/sys/kernel/security", "securityfs", NULL,              MS_NOSUID|MS_NOEXEC|MS_NODEV, false },
        { "tmpfs",    "/dev/shm",               "tmpfs",    "mode=1777",         MS_NOSUID|MS_NODEV|MS_STRICTATIME, true },
        { "devpts",   "/dev/pts",               "devpts",   "mode=620,gid=" STRINGIFY(TTY_GID), MS_NOSUID|MS_NOEXEC, false },
        { "tmpfs",    "/run",                   "tmpfs",    "mode=755",          MS_NOSUID|MS_NODEV|MS_STRICTATIME, true },
        { "tmpfs",    "/sys/fs/cgroup",         "tmpfs",    "mode=755",          MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME, false },
        { "cgroup",   "/sys/fs/cgroup/systemd", "cgroup",   "none,name=systemd", MS_NOSUID|MS_NOEXEC|MS_NODEV, false },
};

/* These are API file systems that might be mounted by other software,
 * we just list them here so that we know that we should ignore them */

static const char ignore_paths[] =
        /* SELinux file systems */
        "/sys/fs/selinux\0"
        "/selinux\0"
        /* Legacy cgroup mount points */
        "/dev/cgroup\0"
        "/cgroup\0"
        /* Legacy kernel file system */
        "/proc/bus/usb\0"
        /* Container bind mounts */
        "/proc/sys\0"
        "/dev/console\0"
        "/proc/kmsg\0"
        "/etc/localtime\0"
        "/etc/timezone\0"
        "/etc/machine-id\0";

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
        const char *i;

        NULSTR_FOREACH(i, ignore_paths)
                if (path_equal(path, i))
                        return true;

        return false;
}

static int mount_one(const MountPoint *p, bool relabel) {
        int r;

        assert(p);

        /* Relabel first, just in case */
        if (relabel)
                label_fix(p->where, true, true);

        if ((r = path_is_mount_point(p->where, true)) < 0)
                return r;

        if (r > 0)
                return 0;

        /* The access mode here doesn't really matter too much, since
         * the mounted file system will take precedence anyway. */
        mkdir_p_label(p->where, 0755);

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
                log_full(p->fatal ? LOG_ERR : LOG_DEBUG, "Failed to mount %s: %s", p->where, strerror(errno));
                return p->fatal ? -errno : 0;
        }

        /* Relabel again, since we now mounted something fresh here */
        if (relabel)
                label_fix(p->where, false, false);

        return 1;
}

int mount_setup_early(void) {
        unsigned i;
        int r = 0;

        assert_cc(N_EARLY_MOUNT <= ELEMENTSOF(mount_table));

        /* Do a minimal mount of /proc and friends to enable the most
         * basic stuff, such as SELinux */
        for (i = 0; i < N_EARLY_MOUNT; i ++)  {
                int j;

                j = mount_one(mount_table + i, false);
                if (r == 0)
                        r = j;
        }

        return r;
}

int mount_cgroup_controllers(char ***join_controllers) {
        int r;
        FILE *f;
        char buf[LINE_MAX];
        Set *controllers;

        /* Mount all available cgroup controllers that are built into the kernel. */

        f = fopen("/proc/cgroups", "re");
        if (!f) {
                log_error("Failed to enumerate cgroup controllers: %m");
                return 0;
        }

        controllers = set_new(string_hash_func, string_compare_func);
        if (!controllers) {
                r = -ENOMEM;
                log_error("Failed to allocate controller set.");
                goto finish;
        }

        /* Ignore the header line */
        (void) fgets(buf, sizeof(buf), f);

        for (;;) {
                char *controller;
                int enabled = 0;

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

                r = set_put(controllers, controller);
                if (r < 0) {
                        log_error("Failed to add controller to set.");
                        free(controller);
                        goto finish;
                }
        }

        for (;;) {
                MountPoint p;
                char *controller, *where, *options;
                char ***k = NULL;

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                if (join_controllers)
                        for (k = join_controllers; *k; k++)
                                if (strv_find(*k, controller))
                                        break;

                if (k && *k) {
                        char **i, **j;

                        for (i = *k, j = *k; *i; i++) {

                                if (!streq(*i, controller)) {
                                        char *t;

                                        t = set_remove(controllers, *i);
                                        if (!t) {
                                                free(*i);
                                                continue;
                                        }
                                        free(t);
                                }

                                *(j++) = *i;
                        }

                        *j = NULL;

                        options = strv_join(*k, ",");
                        if (!options) {
                                log_error("Failed to join options");
                                free(controller);
                                r = -ENOMEM;
                                goto finish;
                        }

                } else {
                        options = controller;
                        controller = NULL;
                }

                where = strappend("/sys/fs/cgroup/", options);
                if (!where) {
                        log_error("Failed to build path");
                        free(options);
                        r = -ENOMEM;
                        goto finish;
                }

                zero(p);
                p.what = "cgroup";
                p.where = where;
                p.type = "cgroup";
                p.options = options;
                p.flags = MS_NOSUID|MS_NOEXEC|MS_NODEV;
                p.fatal = false;

                r = mount_one(&p, true);
                free(controller);
                free(where);

                if (r < 0) {
                        free(options);
                        goto finish;
                }

                if (r > 0 && k && *k) {
                        char **i;

                        for (i = *k; *i; i++) {
                                char *t;

                                t = strappend("/sys/fs/cgroup/", *i);
                                if (!t) {
                                        log_error("Failed to build path");
                                        r = -ENOMEM;
                                        free(options);
                                        goto finish;
                                }

                                r = symlink(options, t);
                                free(t);

                                if (r < 0 && errno != EEXIST) {
                                        log_error("Failed to create symlink: %m");
                                        r = -errno;
                                        free(options);
                                        goto finish;
                                }
                        }
                }

                free(options);
        }

        r = 0;

finish:
        set_free_free(controllers);

        fclose(f);

        return r;
}

static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        /* No need to label /dev twice in a row... */
        if (_unlikely_(ftwbuf->level == 0))
                return FTW_CONTINUE;

        label_fix(fpath, false, false);

        /* /run/initramfs is static data and big, no need to
         * dynamically relabel its contents at boot... */
        if (_unlikely_(ftwbuf->level == 1 &&
                      tflag == FTW_D &&
                      streq(fpath, "/run/initramfs")))
                return FTW_SKIP_SUBTREE;

        return FTW_CONTINUE;
};

int mount_setup(bool loaded_policy) {

        static const char relabel[] =
                "/run/initramfs/root-fsck\0"
                "/run/initramfs/shutdown\0";

        int r;
        unsigned i;
        const char *j;

        for (i = 0; i < ELEMENTSOF(mount_table); i ++) {
                r = mount_one(mount_table + i, true);

                if (r < 0)
                        return r;
        }

        /* Nodes in devtmpfs and /run need to be manually updated for
         * the appropriate labels, after mounting. The other virtual
         * API file systems like /sys and /proc do not need that, they
         * use the same label for all their files. */
        if (loaded_policy) {
                usec_t before_relabel, after_relabel;
                char timespan[FORMAT_TIMESPAN_MAX];

                before_relabel = now(CLOCK_MONOTONIC);

                nftw("/dev", nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);
                nftw("/run", nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);

                /* Explicitly relabel these */
                NULSTR_FOREACH(j, relabel)
                        label_fix(j, true, false);

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabelled /dev and /run in %s.",
                         format_timespan(timespan, sizeof(timespan), after_relabel - before_relabel));
        }

        /* Create a few default symlinks, which are normally created
         * by udevd, but some scripts might need them before we start
         * udevd. */
        dev_setup();

        /* Create a few directories we always want around */
        mkdir_label("/run/systemd", 0755);
        mkdir_label("/run/systemd/system", 0755);

        return 0;
}
