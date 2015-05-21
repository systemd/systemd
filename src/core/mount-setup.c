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
#include <stdlib.h>
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
#include "virt.h"
#include "efivars.h"
#include "smack-util.h"
#include "cgroup-util.h"

typedef enum MountMode {
        MNT_NONE  =        0,
        MNT_FATAL =        1 <<  0,
        MNT_IN_CONTAINER = 1 <<  1,
} MountMode;

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;
        bool (*condition_fn)(void);
        MountMode mode;
} MountPoint;

/* The first three entries we might need before SELinux is up. The
 * fourth (securityfs) is needed by IMA to load a custom policy. The
 * other ones we can delay until SELinux and IMA are loaded. When
 * SMACK is enabled we need smackfs, too, so it's a fifth one. */
#ifdef HAVE_SMACK
#define N_EARLY_MOUNT 5
#else
#define N_EARLY_MOUNT 4
#endif

static const MountPoint mount_table[] = {
        { "sysfs",       "/sys",                      "sysfs",      NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "proc",        "/proc",                     "proc",       NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devtmpfs",    "/dev",                      "devtmpfs",   "mode=755",                MS_NOSUID|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "securityfs",  "/sys/kernel/security",      "securityfs", NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#ifdef HAVE_SMACK
        { "smackfs",     "/sys/fs/smackfs",           "smackfs",    "smackfsdef=*",            MS_NOSUID|MS_NOEXEC|MS_NODEV,
          mac_smack_use, MNT_FATAL                  },
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=1777,smackfsroot=*", MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          mac_smack_use, MNT_FATAL                  },
#endif
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=1777",               MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devpts",      "/dev/pts",                  "devpts",     "mode=620,gid=" STRINGIFY(TTY_GID), MS_NOSUID|MS_NOEXEC,
          NULL,          MNT_IN_CONTAINER           },
#ifdef HAVE_SMACK
        { "tmpfs",       "/run",                      "tmpfs",      "mode=755,smackfsroot=*",  MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          mac_smack_use, MNT_FATAL                  },
#endif
        { "tmpfs",       "/run",                      "tmpfs",      "mode=755",                MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "tmpfs",       "/sys/fs/cgroup",            "tmpfs",      "mode=755",                MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "cgroup",      "/sys/fs/cgroup/systemd",    "cgroup",     "none,name=systemd,xattr", MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_IN_CONTAINER           },
        { "cgroup",      "/sys/fs/cgroup/systemd",    "cgroup",     "none,name=systemd",       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "pstore",      "/sys/fs/pstore",            "pstore",     NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#ifdef ENABLE_EFI
        { "efivarfs",    "/sys/firmware/efi/efivars", "efivarfs",   NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          is_efi_boot,   MNT_NONE                   },
#endif
#ifdef ENABLE_KDBUS
        { "kdbusfs",    "/sys/fs/kdbus",             "kdbusfs",    NULL, MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,       MNT_IN_CONTAINER },
#endif
};

/* These are API file systems that might be mounted by other software,
 * we just list them here so that we know that we should ignore them */

static const char ignore_paths[] =
        /* SELinux file systems */
        "/sys/fs/selinux\0"
        /* Container bind mounts */
        "/proc/sys\0"
        "/dev/console\0"
        "/proc/kmsg\0";

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

        if (p->condition_fn && !p->condition_fn())
                return 0;

        /* Relabel first, just in case */
        if (relabel)
                label_fix(p->where, true, true);

        r = path_is_mount_point(p->where, true);
        if (r < 0 && r != -ENOENT)
                return r;
        if (r > 0)
                return 0;

        /* Skip securityfs in a container */
        if (!(p->mode & MNT_IN_CONTAINER) && detect_container(NULL) > 0)
                return 0;

        /* The access mode here doesn't really matter too much, since
         * the mounted file system will take precedence anyway. */
        if (relabel)
                mkdir_p_label(p->where, 0755);
        else
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
                log_full((p->mode & MNT_FATAL) ? LOG_ERR : LOG_DEBUG, "Failed to mount %s at %s: %m", p->type, p->where);
                return (p->mode & MNT_FATAL) ? -errno : 0;
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
        _cleanup_set_free_free_ Set *controllers = NULL;
        int r;

        /* Mount all available cgroup controllers that are built into the kernel. */

        controllers = set_new(&string_hash_ops);
        if (!controllers)
                return log_oom();

        r = cg_kernel_controllers(controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate cgroup controllers: %m");

        for (;;) {
                _cleanup_free_ char *options = NULL, *controller = NULL, *where = NULL;
                MountPoint p = {
                        .what = "cgroup",
                        .type = "cgroup",
                        .flags = MS_NOSUID|MS_NOEXEC|MS_NODEV,
                        .mode = MNT_IN_CONTAINER,
                };
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
                                        _cleanup_free_ char *t;

                                        t = set_remove(controllers, *i);
                                        if (!t) {
                                                free(*i);
                                                continue;
                                        }
                                }

                                *(j++) = *i;
                        }

                        *j = NULL;

                        options = strv_join(*k, ",");
                        if (!options)
                                return log_oom();
                } else {
                        options = controller;
                        controller = NULL;
                }

                where = strappend("/sys/fs/cgroup/", options);
                if (!where)
                        return log_oom();

                p.where = where;
                p.options = options;

                r = mount_one(&p, true);
                if (r < 0)
                        return r;

                if (r > 0 && k && *k) {
                        char **i;

                        for (i = *k; *i; i++) {
                                _cleanup_free_ char *t = NULL;

                                t = strappend("/sys/fs/cgroup/", *i);
                                if (!t)
                                        return log_oom();

                                r = symlink(options, t);
                                if (r < 0 && errno != EEXIST)
                                        return log_error_errno(errno, "Failed to create symlink %s: %m", t);
                        }
                }
        }

        /* Now that we mounted everything, let's make the tmpfs the
         * cgroup file systems are mounted into read-only. */
        (void) mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755");

        return 0;
}

#if defined(HAVE_SELINUX) || defined(HAVE_SMACK)
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
#endif

int mount_setup(bool loaded_policy) {
        unsigned i;
        int r = 0;

        for (i = 0; i < ELEMENTSOF(mount_table); i ++) {
                int j;

                j = mount_one(mount_table + i, loaded_policy);
                if (r == 0)
                        r = j;
        }

        if (r < 0)
                return r;

#if defined(HAVE_SELINUX) || defined(HAVE_SMACK)
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

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabelled /dev and /run in %s.",
                         format_timespan(timespan, sizeof(timespan), after_relabel - before_relabel, 0));
        }
#endif

        /* Create a few default symlinks, which are normally created
         * by udevd, but some scripts might need them before we start
         * udevd. */
        dev_setup(NULL, UID_INVALID, GID_INVALID);

        /* Mark the root directory as shared in regards to mount
         * propagation. The kernel defaults to "private", but we think
         * it makes more sense to have a default of "shared" so that
         * nspawn and the container tools work out of the box. If
         * specific setups need other settings they can reset the
         * propagation mode to private if needed. */
        if (detect_container(NULL) <= 0)
                if (mount(NULL, "/", NULL, MS_REC|MS_SHARED, NULL) < 0)
                        log_warning_errno(errno, "Failed to set up the root directory for shared mount propagation: %m");

        /* Create a few directories we always want around, Note that
         * sd_booted() checks for /run/systemd/system, so this mkdir
         * really needs to stay for good, otherwise software that
         * copied sd-daemon.c into their sources will misdetect
         * systemd. */
        mkdir_label("/run/systemd", 0755);
        mkdir_label("/run/systemd/system", 0755);
        mkdir_label("/run/systemd/inaccessible", 0000);

        return 0;
}
