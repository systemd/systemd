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
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>
#include <linux/fs.h>

#include "alloc-util.h"
#include "base-filesystem.h"
#include "dev-setup.h"
#include "fd-util.h"
#include "fs-util.h"
#include "label.h"
#include "loop-util.h"
#include "loopback-setup.h"
#include "missing.h"
#include "mkdir.h"
#include "mount-util.h"
#include "namespace.h"
#include "path-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"

#define DEV_MOUNT_OPTIONS (MS_NOSUID|MS_STRICTATIME|MS_NOEXEC)

typedef enum MountMode {
        /* This is ordered by priority! */
        INACCESSIBLE,
        BIND_MOUNT,
        BIND_MOUNT_RECURSIVE,
        PRIVATE_TMP,
        PRIVATE_DEV,
        BIND_DEV,
        EMPTY_DIR,
        SYSFS,
        PROCFS,
        READONLY,
        READWRITE,
        TMPFS,
} MountMode;

typedef struct MountEntry {
        const char *path_const;   /* Memory allocated on stack or static */
        MountMode mode:5;
        bool ignore:1;            /* Ignore if path does not exist? */
        bool has_prefix:1;        /* Already is prefixed by the root dir? */
        bool read_only:1;         /* Shall this mount point be read-only? */
        char *path_malloc;        /* Use this instead of 'path_const' if we had to allocate memory */
        const char *source_const; /* The source path, for bind mounts */
        char *source_malloc;
        const char *options_const;/* Mount options for tmpfs */
        char *options_malloc;
        unsigned long flags;      /* Mount flags used by EMPTY_DIR and TMPFS. Do not include MS_RDONLY here, but please use read_only. */
} MountEntry;

/* If MountAPIVFS= is used, let's mount /sys and /proc into the it, but only as a fallback if the user hasn't mounted
 * something there already. These mounts are hence overriden by any other explicitly configured mounts. */
static const MountEntry apivfs_table[] = {
        { "/proc",               PROCFS,       false },
        { "/dev",                BIND_DEV,     false },
        { "/sys",                SYSFS,        false },
};

/* ProtectKernelTunables= option and the related filesystem APIs */
static const MountEntry protect_kernel_tunables_table[] = {
        { "/proc/sys",           READONLY,     false },
        { "/proc/sysrq-trigger", READONLY,     true  },
        { "/proc/latency_stats", READONLY,     true  },
        { "/proc/mtrr",          READONLY,     true  },
        { "/proc/apm",           READONLY,     true  }, /* Obsolete API, there's no point in permitting access to this, ever */
        { "/proc/acpi",          READONLY,     true  },
        { "/proc/timer_stats",   READONLY,     true  },
        { "/proc/asound",        READONLY,     true  },
        { "/proc/bus",           READONLY,     true  },
        { "/proc/fs",            READONLY,     true  },
        { "/proc/irq",           READONLY,     true  },
        { "/sys",                READONLY,     false },
        { "/sys/kernel/debug",   READONLY,     true  },
        { "/sys/kernel/tracing", READONLY,     true  },
        { "/sys/fs/bpf",         READONLY,     true  },
        { "/sys/fs/cgroup",      READWRITE,    false }, /* READONLY is set by ProtectControlGroups= option */
        { "/sys/fs/selinux",     READWRITE,    true  },
};

/* ProtectKernelModules= option */
static const MountEntry protect_kernel_modules_table[] = {
#if HAVE_SPLIT_USR
        { "/lib/modules",        INACCESSIBLE, true  },
#endif
        { "/usr/lib/modules",    INACCESSIBLE, true  },
};

/*
 * ProtectHome=read-only table, protect $HOME and $XDG_RUNTIME_DIR and rest of
 * system should be protected by ProtectSystem=
 */
static const MountEntry protect_home_read_only_table[] = {
        { "/home",               READONLY,     true  },
        { "/run/user",           READONLY,     true  },
        { "/root",               READONLY,     true  },
};

/* ProtectHome=tmpfs table */
static const MountEntry protect_home_tmpfs_table[] = {
        { "/home",               TMPFS,        true, .read_only = true, .options_const = "mode=0755", .flags = MS_NODEV|MS_STRICTATIME },
        { "/run/user",           TMPFS,        true, .read_only = true, .options_const = "mode=0755", .flags = MS_NODEV|MS_STRICTATIME },
        { "/root",               TMPFS,        true, .read_only = true, .options_const = "mode=0700", .flags = MS_NODEV|MS_STRICTATIME },
};

/* ProtectHome=yes table */
static const MountEntry protect_home_yes_table[] = {
        { "/home",               INACCESSIBLE, true  },
        { "/run/user",           INACCESSIBLE, true  },
        { "/root",               INACCESSIBLE, true  },
};

/* ProtectSystem=yes table */
static const MountEntry protect_system_yes_table[] = {
        { "/usr",                READONLY,     false },
        { "/boot",               READONLY,     true  },
        { "/efi",                READONLY,     true  },
#if HAVE_SPLIT_USR
        { "/lib",                READONLY,     true  },
        { "/lib64",              READONLY,     true  },
        { "/bin",                READONLY,     true  },
#  if HAVE_SPLIT_BIN
        { "/sbin",               READONLY,     true  },
#  endif
#endif
};

/* ProtectSystem=full includes ProtectSystem=yes */
static const MountEntry protect_system_full_table[] = {
        { "/usr",                READONLY,     false },
        { "/boot",               READONLY,     true  },
        { "/efi",                READONLY,     true  },
        { "/etc",                READONLY,     false },
#if HAVE_SPLIT_USR
        { "/lib",                READONLY,     true  },
        { "/lib64",              READONLY,     true  },
        { "/bin",                READONLY,     true  },
#  if HAVE_SPLIT_BIN
        { "/sbin",               READONLY,     true  },
#  endif
#endif
};

/*
 * ProtectSystem=strict table. In this strict mode, we mount everything
 * read-only, except for /proc, /dev, /sys which are the kernel API VFS,
 * which are left writable, but PrivateDevices= + ProtectKernelTunables=
 * protect those, and these options should be fully orthogonal.
 * (And of course /home and friends are also left writable, as ProtectHome=
 * shall manage those, orthogonally).
 */
static const MountEntry protect_system_strict_table[] = {
        { "/",                   READONLY,     false },
        { "/proc",               READWRITE,    false },      /* ProtectKernelTunables= */
        { "/sys",                READWRITE,    false },      /* ProtectKernelTunables= */
        { "/dev",                READWRITE,    false },      /* PrivateDevices= */
        { "/home",               READWRITE,    true  },      /* ProtectHome= */
        { "/run/user",           READWRITE,    true  },      /* ProtectHome= */
        { "/root",               READWRITE,    true  },      /* ProtectHome= */
};

static const char *mount_entry_path(const MountEntry *p) {
        assert(p);

        /* Returns the path of this bind mount. If the malloc()-allocated ->path_buffer field is set we return that,
         * otherwise the stack/static ->path field is returned. */

        return p->path_malloc ?: p->path_const;
}

static bool mount_entry_read_only(const MountEntry *p) {
        assert(p);

        return p->read_only || IN_SET(p->mode, READONLY, INACCESSIBLE);
}

static const char *mount_entry_source(const MountEntry *p) {
        assert(p);

        return p->source_malloc ?: p->source_const;
}

static const char *mount_entry_options(const MountEntry *p) {
        assert(p);

        return p->options_malloc ?: p->options_const;
}

static void mount_entry_done(MountEntry *p) {
        assert(p);

        p->path_malloc = mfree(p->path_malloc);
        p->source_malloc = mfree(p->source_malloc);
        p->options_malloc = mfree(p->options_malloc);
}

static int append_access_mounts(MountEntry **p, char **strv, MountMode mode, bool forcibly_require_prefix) {
        char **i;

        assert(p);

        /* Adds a list of user-supplied READWRITE/READONLY/INACCESSIBLE entries */

        STRV_FOREACH(i, strv) {
                bool ignore = false, needs_prefix = false;
                const char *e = *i;

                /* Look for any prefixes */
                if (startswith(e, "-")) {
                        e++;
                        ignore = true;
                }
                if (startswith(e, "+")) {
                        e++;
                        needs_prefix = true;
                }

                if (!path_is_absolute(e))
                        return -EINVAL;

                *((*p)++) = (MountEntry) {
                        .path_const = e,
                        .mode = mode,
                        .ignore = ignore,
                        .has_prefix = !needs_prefix && !forcibly_require_prefix,
                };
        }

        return 0;
}

static int append_empty_dir_mounts(MountEntry **p, char **strv) {
        char **i;

        assert(p);

        /* Adds tmpfs mounts to provide readable but empty directories. This is primarily used to implement the
         * "/private/" boundary directories for DynamicUser=1. */

        STRV_FOREACH(i, strv) {

                *((*p)++) = (MountEntry) {
                        .path_const = *i,
                        .mode = EMPTY_DIR,
                        .ignore = false,
                        .has_prefix = false,
                        .read_only = true,
                        .options_const = "mode=755",
                        .flags = MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
                };
        }

        return 0;
}

static int append_bind_mounts(MountEntry **p, const BindMount *binds, unsigned n) {
        unsigned i;

        assert(p);

        for (i = 0; i < n; i++) {
                const BindMount *b = binds + i;

                *((*p)++) = (MountEntry) {
                        .path_const = b->destination,
                        .mode = b->recursive ? BIND_MOUNT_RECURSIVE : BIND_MOUNT,
                        .read_only = b->read_only,
                        .source_const = b->source,
                        .ignore = b->ignore_enoent,
                };
        }

        return 0;
}

static int append_tmpfs_mounts(MountEntry **p, const TemporaryFileSystem *tmpfs, unsigned n) {
        unsigned i;
        int r;

        assert(p);

        for (i = 0; i < n; i++) {
                const TemporaryFileSystem *t = tmpfs + i;
                _cleanup_free_ char *o = NULL, *str = NULL;
                unsigned long flags = MS_NODEV|MS_STRICTATIME;
                bool ro = false;

                if (!path_is_absolute(t->path))
                        return -EINVAL;

                if (!isempty(t->options)) {
                        str = strjoin("mode=0755,", t->options);
                        if (!str)
                                return -ENOMEM;

                        r = mount_option_mangle(str, MS_NODEV|MS_STRICTATIME, &flags, &o);
                        if (r < 0)
                                return r;

                        ro = !!(flags & MS_RDONLY);
                        if (ro)
                                flags ^= MS_RDONLY;
                }

                *((*p)++) = (MountEntry) {
                        .path_const = t->path,
                        .mode = TMPFS,
                        .read_only = ro,
                        .options_malloc = o,
                        .flags = flags,
                };

                o = NULL;
        }

        return 0;
}

static int append_static_mounts(MountEntry **p, const MountEntry *mounts, unsigned n, bool ignore_protect) {
        unsigned i;

        assert(p);
        assert(mounts);

        /* Adds a list of static pre-defined entries */

        for (i = 0; i < n; i++)
                *((*p)++) = (MountEntry) {
                        .path_const = mount_entry_path(mounts+i),
                        .mode = mounts[i].mode,
                        .ignore = mounts[i].ignore || ignore_protect,
                };

        return 0;
}

static int append_protect_home(MountEntry **p, ProtectHome protect_home, bool ignore_protect) {
        assert(p);

        switch (protect_home) {

        case PROTECT_HOME_NO:
                return 0;

        case PROTECT_HOME_READ_ONLY:
                return append_static_mounts(p, protect_home_read_only_table, ELEMENTSOF(protect_home_read_only_table), ignore_protect);

        case PROTECT_HOME_TMPFS:
                return append_static_mounts(p, protect_home_tmpfs_table, ELEMENTSOF(protect_home_tmpfs_table), ignore_protect);

        case PROTECT_HOME_YES:
                return append_static_mounts(p, protect_home_yes_table, ELEMENTSOF(protect_home_yes_table), ignore_protect);

        default:
                assert_not_reached("Unexpected ProtectHome= value");
        }
}

static int append_protect_system(MountEntry **p, ProtectSystem protect_system, bool ignore_protect) {
        assert(p);

        switch (protect_system) {

        case PROTECT_SYSTEM_NO:
                return 0;

        case PROTECT_SYSTEM_STRICT:
                return append_static_mounts(p, protect_system_strict_table, ELEMENTSOF(protect_system_strict_table), ignore_protect);

        case PROTECT_SYSTEM_YES:
                return append_static_mounts(p, protect_system_yes_table, ELEMENTSOF(protect_system_yes_table), ignore_protect);

        case PROTECT_SYSTEM_FULL:
                return append_static_mounts(p, protect_system_full_table, ELEMENTSOF(protect_system_full_table), ignore_protect);

        default:
                assert_not_reached("Unexpected ProtectSystem= value");
        }
}

static int mount_path_compare(const void *a, const void *b) {
        const MountEntry *p = a, *q = b;
        int d;

        /* If the paths are not equal, then order prefixes first */
        d = path_compare(mount_entry_path(p), mount_entry_path(q));
        if (d != 0)
                return d;

        /* If the paths are equal, check the mode */
        if (p->mode < q->mode)
                return -1;

        if (p->mode > q->mode)
                return 1;

        return 0;
}

static int prefix_where_needed(MountEntry *m, unsigned n, const char *root_directory) {
        unsigned i;

        /* Prefixes all paths in the bind mount table with the root directory if it is specified and the entry needs
         * that. */

        if (!root_directory)
                return 0;

        for (i = 0; i < n; i++) {
                char *s;

                if (m[i].has_prefix)
                        continue;

                s = prefix_root(root_directory, mount_entry_path(m+i));
                if (!s)
                        return -ENOMEM;

                free_and_replace(m[i].path_malloc, s);
                m[i].has_prefix = true;
        }

        return 0;
}

static void drop_duplicates(MountEntry *m, unsigned *n) {
        MountEntry *f, *t, *previous;

        assert(m);
        assert(n);

        /* Drops duplicate entries. Expects that the array is properly ordered already. */

        for (f = m, t = m, previous = NULL; f < m + *n; f++) {

                /* The first one wins (which is the one with the more restrictive mode), see mount_path_compare()
                 * above. */
                if (previous && path_equal(mount_entry_path(f), mount_entry_path(previous))) {
                        log_debug("%s is duplicate.", mount_entry_path(f));
                        previous->read_only = previous->read_only || mount_entry_read_only(f); /* Propagate the read-only flag to the remaining entry */
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                previous = t;
                t++;
        }

        *n = t - m;
}

static void drop_inaccessible(MountEntry *m, unsigned *n) {
        MountEntry *f, *t;
        const char *clear = NULL;

        assert(m);
        assert(n);

        /* Drops all entries obstructed by another entry further up the tree. Expects that the array is properly
         * ordered already. */

        for (f = m, t = m; f < m + *n; f++) {

                /* If we found a path set for INACCESSIBLE earlier, and this entry has it as prefix we should drop
                 * it, as inaccessible paths really should drop the entire subtree. */
                if (clear && path_startswith(mount_entry_path(f), clear)) {
                        log_debug("%s is masked by %s.", mount_entry_path(f), clear);
                        mount_entry_done(f);
                        continue;
                }

                clear = f->mode == INACCESSIBLE ? mount_entry_path(f) : NULL;

                *t = *f;
                t++;
        }

        *n = t - m;
}

static void drop_nop(MountEntry *m, unsigned *n) {
        MountEntry *f, *t;

        assert(m);
        assert(n);

        /* Drops all entries which have an immediate parent that has the same type, as they are redundant. Assumes the
         * list is ordered by prefixes. */

        for (f = m, t = m; f < m + *n; f++) {

                /* Only suppress such subtrees for READONLY and READWRITE entries */
                if (IN_SET(f->mode, READONLY, READWRITE)) {
                        MountEntry *p;
                        bool found = false;

                        /* Now let's find the first parent of the entry we are looking at. */
                        for (p = t-1; p >= m; p--) {
                                if (path_startswith(mount_entry_path(f), mount_entry_path(p))) {
                                        found = true;
                                        break;
                                }
                        }

                        /* We found it, let's see if it's the same mode, if so, we can drop this entry */
                        if (found && p->mode == f->mode) {
                                log_debug("%s is redundant by %s", mount_entry_path(f), mount_entry_path(p));
                                mount_entry_done(f);
                                continue;
                        }
                }

                *t = *f;
                t++;
        }

        *n = t - m;
}

static void drop_outside_root(const char *root_directory, MountEntry *m, unsigned *n) {
        MountEntry *f, *t;

        assert(m);
        assert(n);

        /* Nothing to do */
        if (!root_directory)
                return;

        /* Drops all mounts that are outside of the root directory. */

        for (f = m, t = m; f < m + *n; f++) {

                if (!path_startswith(mount_entry_path(f), root_directory)) {
                        log_debug("%s is outside of root directory.", mount_entry_path(f));
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                t++;
        }

        *n = t - m;
}

static int clone_device_node(const char *d, const char *temporary_mount) {
        const char *dn;
        struct stat st;
        int r;

        if (stat(d, &st) < 0) {
                if (errno == ENOENT)
                        return 0;
                return -errno;
        }

        if (!S_ISBLK(st.st_mode) &&
            !S_ISCHR(st.st_mode))
                return -EINVAL;

        if (st.st_rdev == 0)
                return 0;

        dn = strjoina(temporary_mount, d);

        mac_selinux_create_file_prepare(d, st.st_mode);
        r = mknod(dn, st.st_mode, st.st_rdev);
        mac_selinux_create_file_clear();
        if (r < 0)
                return log_debug_errno(errno, "mknod failed for %s: %m", d);

        return 1;
}

static int mount_private_dev(MountEntry *m) {
        static const char devnodes[] =
                "/dev/null\0"
                "/dev/zero\0"
                "/dev/full\0"
                "/dev/random\0"
                "/dev/urandom\0"
                "/dev/tty\0";

        char temporary_mount[] = "/tmp/namespace-dev-XXXXXX";
        const char *d, *dev = NULL, *devpts = NULL, *devshm = NULL, *devhugepages = NULL, *devmqueue = NULL, *devlog = NULL, *devptmx = NULL;
        _cleanup_umask_ mode_t u;
        int r;

        assert(m);

        u = umask(0000);

        if (!mkdtemp(temporary_mount))
                return -errno;

        dev = strjoina(temporary_mount, "/dev");
        (void) mkdir(dev, 0755);
        if (mount("tmpfs", dev, "tmpfs", DEV_MOUNT_OPTIONS, "mode=755") < 0) {
                r = -errno;
                goto fail;
        }

        devpts = strjoina(temporary_mount, "/dev/pts");
        (void) mkdir(devpts, 0755);
        if (mount("/dev/pts", devpts, NULL, MS_BIND, NULL) < 0) {
                r = -errno;
                goto fail;
        }

        /* /dev/ptmx can either be a device node or a symlink to /dev/pts/ptmx
         * when /dev/ptmx a device node, /dev/pts/ptmx has 000 permissions making it inaccessible
         * thus, in that case make a clone
         *
         * in nspawn and other containers it will be a symlink, in that case make it a symlink
         */
        r = is_symlink("/dev/ptmx");
        if (r < 0)
                goto fail;
        if (r > 0) {
                devptmx = strjoina(temporary_mount, "/dev/ptmx");
                if (symlink("pts/ptmx", devptmx) < 0) {
                        r = -errno;
                        goto fail;
                }
        } else {
                r = clone_device_node("/dev/ptmx", temporary_mount);
                if (r < 0)
                        goto fail;
                if (r == 0) {
                        r = -ENXIO;
                        goto fail;
                }
        }

        devshm = strjoina(temporary_mount, "/dev/shm");
        (void) mkdir(devshm, 0755);
        r = mount("/dev/shm", devshm, NULL, MS_BIND, NULL);
        if (r < 0) {
                r = -errno;
                goto fail;
        }

        devmqueue = strjoina(temporary_mount, "/dev/mqueue");
        (void) mkdir(devmqueue, 0755);
        (void) mount("/dev/mqueue", devmqueue, NULL, MS_BIND, NULL);

        devhugepages = strjoina(temporary_mount, "/dev/hugepages");
        (void) mkdir(devhugepages, 0755);
        (void) mount("/dev/hugepages", devhugepages, NULL, MS_BIND, NULL);

        devlog = strjoina(temporary_mount, "/dev/log");
        (void) symlink("/run/systemd/journal/dev-log", devlog);

        NULSTR_FOREACH(d, devnodes) {
                r = clone_device_node(d, temporary_mount);
                if (r < 0)
                        goto fail;
        }

        dev_setup(temporary_mount, UID_INVALID, GID_INVALID);

        /* Create the /dev directory if missing. It is more likely to be
         * missing when the service is started with RootDirectory. This is
         * consistent with mount units creating the mount points when missing.
         */
        (void) mkdir_p_label(mount_entry_path(m), 0755);

        /* Unmount everything in old /dev */
        umount_recursive(mount_entry_path(m), 0);
        if (mount(dev, mount_entry_path(m), NULL, MS_MOVE, NULL) < 0) {
                r = -errno;
                goto fail;
        }

        rmdir(dev);
        rmdir(temporary_mount);

        return 0;

fail:
        if (devpts)
                umount(devpts);

        if (devshm)
                umount(devshm);

        if (devhugepages)
                umount(devhugepages);

        if (devmqueue)
                umount(devmqueue);

        umount(dev);
        rmdir(dev);
        rmdir(temporary_mount);

        return r;
}

static int mount_bind_dev(const MountEntry *m) {
        int r;

        assert(m);

        /* Implements the little brother of mount_private_dev(): simply bind mounts the host's /dev into the service's
         * /dev. This is only used when RootDirectory= is set. */

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m), NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /dev is already mounted: %m");
        if (r > 0) /* make this a NOP if /dev is already a mount point */
                return 0;

        if (mount("/dev", mount_entry_path(m), NULL, MS_BIND|MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to bind mount %s: %m", mount_entry_path(m));

        return 1;
}

static int mount_sysfs(const MountEntry *m) {
        int r;

        assert(m);

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m), NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /sys is already mounted: %m");
        if (r > 0) /* make this a NOP if /sys is already a mount point */
                return 0;

        /* Bind mount the host's version so that we get all child mounts of it, too. */
        if (mount("/sys", mount_entry_path(m), NULL, MS_BIND|MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to mount %s: %m", mount_entry_path(m));

        return 1;
}

static int mount_procfs(const MountEntry *m) {
        int r;

        assert(m);

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m), NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /proc is already mounted: %m");
        if (r > 0) /* make this a NOP if /proc is already a mount point */
                return 0;

        /* Mount a new instance, so that we get the one that matches our user namespace, if we are running in one */
        if (mount("proc", mount_entry_path(m), "proc", MS_NOSUID|MS_NOEXEC|MS_NODEV, NULL) < 0)
                return log_debug_errno(errno, "Failed to mount %s: %m", mount_entry_path(m));

        return 1;
}

static int mount_tmpfs(const MountEntry *m) {
        assert(m);

        /* First, get rid of everything that is below if there is anything. Then, overmount with our new tmpfs */

        (void) mkdir_p_label(mount_entry_path(m), 0755);
        (void) umount_recursive(mount_entry_path(m), 0);

        if (mount("tmpfs", mount_entry_path(m), "tmpfs", m->flags, mount_entry_options(m)) < 0)
                return log_debug_errno(errno, "Failed to mount %s: %m", mount_entry_path(m));

        return 1;
}

static int mount_entry_chase(
                const char *root_directory,
                const MountEntry *m,
                const char *path,
                bool chase_nonexistent,
                char **location) {

        char *chased;
        int r;

        assert(m);

        /* Since mount() will always follow symlinks and we need to take the different root directory into account we
         * chase the symlinks on our own first. This is called for the destination path, as well as the source path (if
         * that applies). The result is stored in "location". */

        r = chase_symlinks(path, root_directory, CHASE_TRAIL_SLASH | (chase_nonexistent ? CHASE_NONEXISTENT : 0), &chased);
        if (r == -ENOENT && m->ignore) {
                log_debug_errno(r, "Path %s does not exist, ignoring.", path);
                return 0;
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to follow symlinks on %s: %m", path);

        log_debug("Followed symlinks %s → %s.", path, chased);

        free(*location);
        *location = chased;

        return 1;
}

static int apply_mount(
                const char *root_directory,
                MountEntry *m) {

        bool rbind = true, make = false;
        const char *what;
        int r;

        assert(m);

        r = mount_entry_chase(root_directory, m, mount_entry_path(m), !IN_SET(m->mode, INACCESSIBLE, READONLY, READWRITE), &m->path_malloc);
        if (r <= 0)
                return r;

        log_debug("Applying namespace mount on %s", mount_entry_path(m));

        switch (m->mode) {

        case INACCESSIBLE: {
                struct stat target;

                /* First, get rid of everything that is below if there
                 * is anything... Then, overmount it with an
                 * inaccessible path. */
                (void) umount_recursive(mount_entry_path(m), 0);

                if (lstat(mount_entry_path(m), &target) < 0)
                        return log_debug_errno(errno, "Failed to lstat() %s to determine what to mount over it: %m", mount_entry_path(m));

                what = mode_to_inaccessible_node(target.st_mode);
                if (!what) {
                        log_debug("File type not supported for inaccessible mounts. Note that symlinks are not allowed");
                        return -ELOOP;
                }
                break;
        }

        case READONLY:
        case READWRITE:
                r = path_is_mount_point(mount_entry_path(m), root_directory, 0);
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine whether %s is already a mount point: %m", mount_entry_path(m));
                if (r > 0) /* Nothing to do here, it is already a mount. We just later toggle the MS_RDONLY bit for the mount point if needed. */
                        return 0;
                /* This isn't a mount point yet, let's make it one. */
                what = mount_entry_path(m);
                break;

        case BIND_MOUNT:
                rbind = false;

                _fallthrough_;
        case BIND_MOUNT_RECURSIVE:
                /* Also chase the source mount */

                r = mount_entry_chase(root_directory, m, mount_entry_source(m), false, &m->source_malloc);
                if (r <= 0)
                        return r;

                what = mount_entry_source(m);
                make = true;
                break;

        case EMPTY_DIR:
        case TMPFS:
                return mount_tmpfs(m);

        case PRIVATE_TMP:
                what = mount_entry_source(m);
                make = true;
                break;

        case PRIVATE_DEV:
                return mount_private_dev(m);

        case BIND_DEV:
                return mount_bind_dev(m);

        case SYSFS:
                return mount_sysfs(m);

        case PROCFS:
                return mount_procfs(m);

        default:
                assert_not_reached("Unknown mode");
        }

        assert(what);

        if (mount(what, mount_entry_path(m), NULL, MS_BIND|(rbind ? MS_REC : 0), NULL) < 0) {
                bool try_again = false;
                r = -errno;

                if (r == -ENOENT && make) {
                        struct stat st;

                        /* Hmm, either the source or the destination are missing. Let's see if we can create the destination, then try again */

                        if (stat(what, &st) >= 0) {

                                (void) mkdir_parents(mount_entry_path(m), 0755);

                                if (S_ISDIR(st.st_mode))
                                        try_again = mkdir(mount_entry_path(m), 0755) >= 0;
                                else
                                        try_again = touch(mount_entry_path(m)) >= 0;
                        }
                }

                if (try_again) {
                        if (mount(what, mount_entry_path(m), NULL, MS_BIND|(rbind ? MS_REC : 0), NULL) < 0)
                                r = -errno;
                        else
                                r = 0;
                }

                if (r < 0)
                        return log_debug_errno(r, "Failed to mount %s to %s: %m", what, mount_entry_path(m));
        }

        log_debug("Successfully mounted %s to %s", what, mount_entry_path(m));
        return 0;
}

static int make_read_only(const MountEntry *m, char **blacklist, FILE *proc_self_mountinfo) {
        int r = 0;

        assert(m);
        assert(proc_self_mountinfo);

        if (mount_entry_read_only(m)) {
                if (IN_SET(m->mode, EMPTY_DIR, TMPFS)) {
                        /* Make superblock readonly */
                        if (mount(NULL, mount_entry_path(m), NULL, MS_REMOUNT | MS_RDONLY | m->flags, mount_entry_options(m)) < 0)
                                r = -errno;
                } else
                        r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), true, blacklist, proc_self_mountinfo);
        } else if (m->mode == PRIVATE_DEV) {
                /* Superblock can be readonly but the submounts can't */
                if (mount(NULL, mount_entry_path(m), NULL, MS_REMOUNT|DEV_MOUNT_OPTIONS|MS_RDONLY, NULL) < 0)
                        r = -errno;
        } else
                return 0;

        /* Not that we only turn on the MS_RDONLY flag here, we never turn it off. Something that was marked read-only
         * already stays this way. This improves compatibility with container managers, where we won't attempt to undo
         * read-only mounts already applied. */

        if (r == -ENOENT && m->ignore)
                r = 0;

        return r;
}

static bool namespace_info_mount_apivfs(const char *root_directory, const NamespaceInfo *ns_info) {
        assert(ns_info);

        /*
         * ProtectControlGroups= and ProtectKernelTunables= imply MountAPIVFS=,
         * since to protect the API VFS mounts, they need to be around in the
         * first place... and RootDirectory= or RootImage= need to be set.
         */

        /* root_directory should point to a mount point */
        return root_directory &&
                (ns_info->mount_apivfs ||
                 ns_info->protect_control_groups ||
                 ns_info->protect_kernel_tunables);
}

static unsigned namespace_calculate_mounts(
                const char* root_directory,
                const NamespaceInfo *ns_info,
                char** read_write_paths,
                char** read_only_paths,
                char** inaccessible_paths,
                char** empty_directories,
                unsigned n_bind_mounts,
                unsigned n_temporary_filesystems,
                const char* tmp_dir,
                const char* var_tmp_dir,
                ProtectHome protect_home,
                ProtectSystem protect_system) {

        unsigned protect_home_cnt;
        unsigned protect_system_cnt =
                (protect_system == PROTECT_SYSTEM_STRICT ?
                 ELEMENTSOF(protect_system_strict_table) :
                 ((protect_system == PROTECT_SYSTEM_FULL) ?
                  ELEMENTSOF(protect_system_full_table) :
                  ((protect_system == PROTECT_SYSTEM_YES) ?
                   ELEMENTSOF(protect_system_yes_table) : 0)));

        protect_home_cnt =
                (protect_home == PROTECT_HOME_YES ?
                 ELEMENTSOF(protect_home_yes_table) :
                 ((protect_home == PROTECT_HOME_READ_ONLY) ?
                  ELEMENTSOF(protect_home_read_only_table) :
                  ((protect_home == PROTECT_HOME_TMPFS) ?
                   ELEMENTSOF(protect_home_tmpfs_table) : 0)));

        return !!tmp_dir + !!var_tmp_dir +
                strv_length(read_write_paths) +
                strv_length(read_only_paths) +
                strv_length(inaccessible_paths) +
                strv_length(empty_directories) +
                n_bind_mounts +
                n_temporary_filesystems +
                ns_info->private_dev +
                (ns_info->protect_kernel_tunables ? ELEMENTSOF(protect_kernel_tunables_table) : 0) +
                (ns_info->protect_control_groups ? 1 : 0) +
                (ns_info->protect_kernel_modules ? ELEMENTSOF(protect_kernel_modules_table) : 0) +
                protect_home_cnt + protect_system_cnt +
                (namespace_info_mount_apivfs(root_directory, ns_info) ? ELEMENTSOF(apivfs_table) : 0);
}

int setup_namespace(
                const char* root_directory,
                const char* root_image,
                const NamespaceInfo *ns_info,
                char** read_write_paths,
                char** read_only_paths,
                char** inaccessible_paths,
                char** empty_directories,
                const BindMount *bind_mounts,
                unsigned n_bind_mounts,
                const TemporaryFileSystem *temporary_filesystems,
                unsigned n_temporary_filesystems,
                const char* tmp_dir,
                const char* var_tmp_dir,
                ProtectHome protect_home,
                ProtectSystem protect_system,
                unsigned long mount_flags,
                DissectImageFlags dissect_image_flags) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_free_ void *root_hash = NULL;
        MountEntry *m, *mounts = NULL;
        size_t root_hash_size = 0;
        bool make_slave = false;
        const char *root;
        unsigned n_mounts;
        bool require_prefix = false;
        int r = 0;

        assert(ns_info);

        if (mount_flags == 0)
                mount_flags = MS_SHARED;

        if (root_image) {
                dissect_image_flags |= DISSECT_IMAGE_REQUIRE_ROOT;

                if (protect_system == PROTECT_SYSTEM_STRICT && strv_isempty(read_write_paths))
                        dissect_image_flags |= DISSECT_IMAGE_READ_ONLY;

                r = loop_device_make_by_path(root_image,
                                             dissect_image_flags & DISSECT_IMAGE_READ_ONLY ? O_RDONLY : O_RDWR,
                                             &loop_device);
                if (r < 0)
                        return r;

                r = root_hash_load(root_image, &root_hash, &root_hash_size);
                if (r < 0)
                        return r;

                r = dissect_image(loop_device->fd, root_hash, root_hash_size, dissect_image_flags, &dissected_image);
                if (r < 0)
                        return r;

                r = dissected_image_decrypt(dissected_image, NULL, root_hash, root_hash_size, dissect_image_flags, &decrypted_image);
                if (r < 0)
                        return r;
        }

        if (root_directory)
                root = root_directory;
        else if (root_image || n_bind_mounts > 0 || n_temporary_filesystems > 0) {

                /* If we are booting from an image, create a mount point for the image, if it's still missing. We use
                 * the same mount point for all images, which is safe, since they all live in their own namespaces
                 * after all, and hence won't see each other. We also use such a root directory whenever there are bind
                 * mounts configured, so that their source mounts are never obstructed by mounts we already applied
                 * while we are applying them. */

                root = "/run/systemd/unit-root";
                (void) mkdir_label(root, 0700);
                require_prefix = true;
        } else
                root = NULL;

        n_mounts = namespace_calculate_mounts(
                        root,
                        ns_info,
                        read_write_paths,
                        read_only_paths,
                        inaccessible_paths,
                        empty_directories,
                        n_bind_mounts,
                        n_temporary_filesystems,
                        tmp_dir, var_tmp_dir,
                        protect_home, protect_system);

        /* Set mount slave mode */
        if (root || n_mounts > 0)
                make_slave = true;

        if (n_mounts > 0) {
                m = mounts = (MountEntry *) alloca0(n_mounts * sizeof(MountEntry));
                r = append_access_mounts(&m, read_write_paths, READWRITE, require_prefix);
                if (r < 0)
                        goto finish;

                r = append_access_mounts(&m, read_only_paths, READONLY, require_prefix);
                if (r < 0)
                        goto finish;

                r = append_access_mounts(&m, inaccessible_paths, INACCESSIBLE, require_prefix);
                if (r < 0)
                        goto finish;

                r = append_empty_dir_mounts(&m, empty_directories);
                if (r < 0)
                        goto finish;

                r = append_bind_mounts(&m, bind_mounts, n_bind_mounts);
                if (r < 0)
                        goto finish;

                r = append_tmpfs_mounts(&m, temporary_filesystems, n_temporary_filesystems);
                if (r < 0)
                        goto finish;

                if (tmp_dir) {
                        *(m++) = (MountEntry) {
                                .path_const = "/tmp",
                                .mode = PRIVATE_TMP,
                                .source_const = tmp_dir,
                        };
                }

                if (var_tmp_dir) {
                        *(m++) = (MountEntry) {
                                .path_const = "/var/tmp",
                                .mode = PRIVATE_TMP,
                                .source_const = var_tmp_dir,
                        };
                }

                if (ns_info->private_dev) {
                        *(m++) = (MountEntry) {
                                .path_const = "/dev",
                                .mode = PRIVATE_DEV,
                        };
                }

                if (ns_info->protect_kernel_tunables) {
                        r = append_static_mounts(&m, protect_kernel_tunables_table, ELEMENTSOF(protect_kernel_tunables_table), ns_info->ignore_protect_paths);
                        if (r < 0)
                                goto finish;
                }

                if (ns_info->protect_kernel_modules) {
                        r = append_static_mounts(&m, protect_kernel_modules_table, ELEMENTSOF(protect_kernel_modules_table), ns_info->ignore_protect_paths);
                        if (r < 0)
                                goto finish;
                }

                if (ns_info->protect_control_groups) {
                        *(m++) = (MountEntry) {
                                .path_const = "/sys/fs/cgroup",
                                .mode = READONLY,
                        };
                }

                r = append_protect_home(&m, protect_home, ns_info->ignore_protect_paths);
                if (r < 0)
                        goto finish;

                r = append_protect_system(&m, protect_system, false);
                if (r < 0)
                        goto finish;

                if (namespace_info_mount_apivfs(root, ns_info)) {
                        r = append_static_mounts(&m, apivfs_table, ELEMENTSOF(apivfs_table), ns_info->ignore_protect_paths);
                        if (r < 0)
                                goto finish;
                }

                assert(mounts + n_mounts == m);

                /* Prepend the root directory where that's necessary */
                r = prefix_where_needed(mounts, n_mounts, root);
                if (r < 0)
                        goto finish;

                qsort(mounts, n_mounts, sizeof(MountEntry), mount_path_compare);

                drop_duplicates(mounts, &n_mounts);
                drop_outside_root(root, mounts, &n_mounts);
                drop_inaccessible(mounts, &n_mounts);
                drop_nop(mounts, &n_mounts);
        }

        if (unshare(CLONE_NEWNS) < 0) {
                r = -errno;
                goto finish;
        }

        if (make_slave) {
                /* Remount / as SLAVE so that nothing now mounted in the namespace
                   shows up in the parent */
                if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        if (root_image) {
                /* A root image is specified, mount it to the right place */
                r = dissected_image_mount(dissected_image, root, UID_INVALID, dissect_image_flags);
                if (r < 0)
                        goto finish;

                if (decrypted_image) {
                        r = decrypted_image_relinquish(decrypted_image);
                        if (r < 0)
                                goto finish;
                }

                loop_device_relinquish(loop_device);

        } else if (root_directory) {

                /* A root directory is specified. Turn its directory into bind mount, if it isn't one yet. */
                r = path_is_mount_point(root, NULL, AT_SYMLINK_FOLLOW);
                if (r < 0)
                        goto finish;
                if (r == 0) {
                        if (mount(root, root, NULL, MS_BIND|MS_REC, NULL) < 0) {
                                r = -errno;
                                goto finish;
                        }
                }

        } else if (root) {

                /* Let's mount the main root directory to the root directory to use */
                if (mount("/", root, NULL, MS_BIND|MS_REC, NULL) < 0) {
                        r = -errno;
                        goto finish;
                }
        }

        /* Try to set up the new root directory before mounting anything else there. */
        if (root_image || root_directory)
                (void) base_filesystem_create(root, UID_INVALID, GID_INVALID);

        if (n_mounts > 0) {
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
                char **blacklist;
                unsigned j;

                /* Open /proc/self/mountinfo now as it may become unavailable if we mount anything on top of /proc.
                 * For example, this is the case with the option: 'InaccessiblePaths=/proc' */
                proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!proc_self_mountinfo) {
                        r = -errno;
                        goto finish;
                }

                /* First round, add in all special mounts we need */
                for (m = mounts; m < mounts + n_mounts; ++m) {
                        r = apply_mount(root, m);
                        if (r < 0)
                                goto finish;
                }

                /* Create a blacklist we can pass to bind_mount_recursive() */
                blacklist = newa(char*, n_mounts+1);
                for (j = 0; j < n_mounts; j++)
                        blacklist[j] = (char*) mount_entry_path(mounts+j);
                blacklist[j] = NULL;

                /* Second round, flip the ro bits if necessary. */
                for (m = mounts; m < mounts + n_mounts; ++m) {
                        r = make_read_only(m, blacklist, proc_self_mountinfo);
                        if (r < 0)
                                goto finish;
                }
        }

        if (root) {
                /* MS_MOVE does not work on MS_SHARED so the remount MS_SHARED will be done later */
                r = mount_move_root(root);
                if (r < 0)
                        goto finish;
        }

        /* Remount / as the desired mode. Note that this will not
         * reestablish propagation from our side to the host, since
         * what's disconnected is disconnected. */
        if (mount(NULL, "/", NULL, mount_flags | MS_REC, NULL) < 0) {
                r = -errno;
                goto finish;
        }

        r = 0;

finish:
        for (m = mounts; m < mounts + n_mounts; m++)
                mount_entry_done(m);

        return r;
}

void bind_mount_free_many(BindMount *b, unsigned n) {
        unsigned i;

        assert(b || n == 0);

        for (i = 0; i < n; i++) {
                free(b[i].source);
                free(b[i].destination);
        }

        free(b);
}

int bind_mount_add(BindMount **b, unsigned *n, const BindMount *item) {
        _cleanup_free_ char *s = NULL, *d = NULL;
        BindMount *c;

        assert(b);
        assert(n);
        assert(item);

        s = strdup(item->source);
        if (!s)
                return -ENOMEM;

        d = strdup(item->destination);
        if (!d)
                return -ENOMEM;

        c = reallocarray(*b, *n + 1, sizeof(BindMount));
        if (!c)
                return -ENOMEM;

        *b = c;

        c[(*n) ++] = (BindMount) {
                .source = s,
                .destination = d,
                .read_only = item->read_only,
                .recursive = item->recursive,
                .ignore_enoent = item->ignore_enoent,
        };

        s = d = NULL;
        return 0;
}

void temporary_filesystem_free_many(TemporaryFileSystem *t, unsigned n) {
        unsigned i;

        assert(t || n == 0);

        for (i = 0; i < n; i++) {
                free(t[i].path);
                free(t[i].options);
        }

        free(t);
}

int temporary_filesystem_add(
                TemporaryFileSystem **t,
                unsigned *n,
                const char *path,
                const char *options) {

        _cleanup_free_ char *p = NULL, *o = NULL;
        TemporaryFileSystem *c;

        assert(t);
        assert(n);
        assert(path);

        p = strdup(path);
        if (!p)
                return -ENOMEM;

        if (!isempty(options)) {
                o = strdup(options);
                if (!o)
                        return -ENOMEM;
        }

        c = reallocarray(*t, *n + 1, sizeof(TemporaryFileSystem));
        if (!c)
                return -ENOMEM;

        *t = c;

        c[(*n) ++] = (TemporaryFileSystem) {
                .path = p,
                .options = o,
        };

        p = o = NULL;
        return 0;
}

static int setup_one_tmp_dir(const char *id, const char *prefix, char **path) {
        _cleanup_free_ char *x = NULL;
        char bid[SD_ID128_STRING_MAX];
        sd_id128_t boot_id;
        int r;

        assert(id);
        assert(prefix);
        assert(path);

        /* We include the boot id in the directory so that after a
         * reboot we can easily identify obsolete directories. */

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        x = strjoin(prefix, "/systemd-private-", sd_id128_to_string(boot_id, bid), "-", id, "-XXXXXX");
        if (!x)
                return -ENOMEM;

        RUN_WITH_UMASK(0077)
                if (!mkdtemp(x))
                        return -errno;

        RUN_WITH_UMASK(0000) {
                char *y;

                y = strjoina(x, "/tmp");

                if (mkdir(y, 0777 | S_ISVTX) < 0)
                        return -errno;
        }

        *path = x;
        x = NULL;

        return 0;
}

int setup_tmp_dirs(const char *id, char **tmp_dir, char **var_tmp_dir) {
        char *a, *b;
        int r;

        assert(id);
        assert(tmp_dir);
        assert(var_tmp_dir);

        r = setup_one_tmp_dir(id, "/tmp", &a);
        if (r < 0)
                return r;

        r = setup_one_tmp_dir(id, "/var/tmp", &b);
        if (r < 0) {
                char *t;

                t = strjoina(a, "/tmp");
                rmdir(t);
                rmdir(a);

                free(a);
                return r;
        }

        *tmp_dir = a;
        *var_tmp_dir = b;

        return 0;
}

int setup_netns(int netns_storage_socket[2]) {
        _cleanup_close_ int netns = -1;
        int r, q;

        assert(netns_storage_socket);
        assert(netns_storage_socket[0] >= 0);
        assert(netns_storage_socket[1] >= 0);

        /* We use the passed socketpair as a storage buffer for our
         * namespace reference fd. Whatever process runs this first
         * shall create a new namespace, all others should just join
         * it. To serialize that we use a file lock on the socket
         * pair.
         *
         * It's a bit crazy, but hey, works great! */

        if (lockf(netns_storage_socket[0], F_LOCK, 0) < 0)
                return -errno;

        netns = receive_one_fd(netns_storage_socket[0], MSG_DONTWAIT);
        if (netns == -EAGAIN) {
                /* Nothing stored yet, so let's create a new namespace */

                if (unshare(CLONE_NEWNET) < 0) {
                        r = -errno;
                        goto fail;
                }

                loopback_setup();

                netns = open("/proc/self/ns/net", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (netns < 0) {
                        r = -errno;
                        goto fail;
                }

                r = 1;

        } else if (netns < 0) {
                r = netns;
                goto fail;

        } else {
                /* Yay, found something, so let's join the namespace */
                if (setns(netns, CLONE_NEWNET) < 0) {
                        r = -errno;
                        goto fail;
                }

                r = 0;
        }

        q = send_one_fd(netns_storage_socket[1], netns, MSG_DONTWAIT);
        if (q < 0) {
                r = q;
                goto fail;
        }

fail:
        (void) lockf(netns_storage_socket[0], F_ULOCK, 0);
        return r;
}

bool ns_type_supported(NamespaceType type) {
        const char *t, *ns_proc;

        t = namespace_type_to_string(type);
        if (!t) /* Don't know how to translate this? Then it's not supported */
                return false;

        ns_proc = strjoina("/proc/self/ns/", t);
        return access(ns_proc, F_OK) == 0;
}

static const char *const protect_home_table[_PROTECT_HOME_MAX] = {
        [PROTECT_HOME_NO] = "no",
        [PROTECT_HOME_YES] = "yes",
        [PROTECT_HOME_READ_ONLY] = "read-only",
        [PROTECT_HOME_TMPFS] = "tmpfs",
};

DEFINE_STRING_TABLE_LOOKUP(protect_home, ProtectHome);

ProtectHome parse_protect_home_or_bool(const char *s) {
        int r;

        r = parse_boolean(s);
        if (r > 0)
                return PROTECT_HOME_YES;
        if (r == 0)
                return PROTECT_HOME_NO;

        return protect_home_from_string(s);
}

static const char *const protect_system_table[_PROTECT_SYSTEM_MAX] = {
        [PROTECT_SYSTEM_NO] = "no",
        [PROTECT_SYSTEM_YES] = "yes",
        [PROTECT_SYSTEM_FULL] = "full",
        [PROTECT_SYSTEM_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP(protect_system, ProtectSystem);

ProtectSystem parse_protect_system_or_bool(const char *s) {
        int r;

        r = parse_boolean(s);
        if (r > 0)
                return PROTECT_SYSTEM_YES;
        if (r == 0)
                return PROTECT_SYSTEM_NO;

        return protect_system_from_string(s);
}

static const char* const namespace_type_table[] = {
        [NAMESPACE_MOUNT] = "mnt",
        [NAMESPACE_CGROUP] = "cgroup",
        [NAMESPACE_UTS] = "uts",
        [NAMESPACE_IPC] = "ipc",
        [NAMESPACE_USER] = "user",
        [NAMESPACE_PID] = "pid",
        [NAMESPACE_NET] = "net",
};

DEFINE_STRING_TABLE_LOOKUP(namespace_type, NamespaceType);
