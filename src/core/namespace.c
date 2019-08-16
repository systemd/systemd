/* SPDX-License-Identifier: LGPL-2.1+ */

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
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "namespace.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "umask-util.h"
#include "user-util.h"

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
        READWRITE_IMPLICIT, /* Should have the lowest priority. */
        _MOUNT_MODE_MAX,
} MountMode;

typedef struct MountEntry {
        const char *path_const;   /* Memory allocated on stack or static */
        MountMode mode:5;
        bool ignore:1;            /* Ignore if path does not exist? */
        bool has_prefix:1;        /* Already is prefixed by the root dir? */
        bool read_only:1;         /* Shall this mount point be read-only? */
        bool nosuid:1;            /* Shall set MS_NOSUID on the mount itself */
        bool applied:1;           /* Already applied */
        char *path_malloc;        /* Use this instead of 'path_const' if we had to allocate memory */
        const char *source_const; /* The source path, for bind mounts */
        char *source_malloc;
        const char *options_const;/* Mount options for tmpfs */
        char *options_malloc;
        unsigned long flags;      /* Mount flags used by EMPTY_DIR and TMPFS. Do not include MS_RDONLY here, but please use read_only. */
        unsigned n_followed;
} MountEntry;

/* If MountAPIVFS= is used, let's mount /sys and /proc into the it, but only as a fallback if the user hasn't mounted
 * something there already. These mounts are hence overridden by any other explicitly configured mounts. */
static const MountEntry apivfs_table[] = {
        { "/proc",               PROCFS,       false },
        { "/dev",                BIND_DEV,     false },
        { "/sys",                SYSFS,        false },
};

/* ProtectKernelTunables= option and the related filesystem APIs */
static const MountEntry protect_kernel_tunables_table[] = {
        { "/proc/acpi",          READONLY,           true  },
        { "/proc/apm",           READONLY,           true  }, /* Obsolete API, there's no point in permitting access to this, ever */
        { "/proc/asound",        READONLY,           true  },
        { "/proc/bus",           READONLY,           true  },
        { "/proc/fs",            READONLY,           true  },
        { "/proc/irq",           READONLY,           true  },
        { "/proc/kallsyms",      INACCESSIBLE,       true  },
        { "/proc/kcore",         INACCESSIBLE,       true  },
        { "/proc/latency_stats", READONLY,           true  },
        { "/proc/mtrr",          READONLY,           true  },
        { "/proc/scsi",          READONLY,           true  },
        { "/proc/sys",           READONLY,           false },
        { "/proc/sysrq-trigger", READONLY,           true  },
        { "/proc/timer_stats",   READONLY,           true  },
        { "/sys",                READONLY,           false },
        { "/sys/fs/bpf",         READONLY,           true  },
        { "/sys/fs/cgroup",      READWRITE_IMPLICIT, false }, /* READONLY is set by ProtectControlGroups= option */
        { "/sys/fs/selinux",     READWRITE_IMPLICIT, true  },
        { "/sys/kernel/debug",   READONLY,           true  },
        { "/sys/kernel/tracing", READONLY,           true  },
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
        { "/",                   READONLY,           false },
        { "/proc",               READWRITE_IMPLICIT, false },      /* ProtectKernelTunables= */
        { "/sys",                READWRITE_IMPLICIT, false },      /* ProtectKernelTunables= */
        { "/dev",                READWRITE_IMPLICIT, false },      /* PrivateDevices= */
        { "/home",               READWRITE_IMPLICIT, true  },      /* ProtectHome= */
        { "/run/user",           READWRITE_IMPLICIT, true  },      /* ProtectHome= */
        { "/root",               READWRITE_IMPLICIT, true  },      /* ProtectHome= */
};

static const char * const mount_mode_table[_MOUNT_MODE_MAX] = {
        [INACCESSIBLE]         = "inaccessible",
        [BIND_MOUNT]           = "bind",
        [BIND_MOUNT_RECURSIVE] = "rbind",
        [PRIVATE_TMP]          = "private-tmp",
        [PRIVATE_DEV]          = "private-dev",
        [BIND_DEV]             = "bind-dev",
        [EMPTY_DIR]            = "empty",
        [SYSFS]                = "sysfs",
        [PROCFS]               = "procfs",
        [READONLY]             = "read-only",
        [READWRITE]            = "read-write",
        [TMPFS]                = "tmpfs",
        [READWRITE_IMPLICIT]   = "rw-implicit",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(mount_mode, MountMode);

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

        /* Adds a list of user-supplied READWRITE/READWRITE_IMPLICIT/READONLY/INACCESSIBLE entries */

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
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path is not absolute: %s", e);

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
                        .read_only = true,
                        .options_const = "mode=755",
                        .flags = MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
                };
        }

        return 0;
}

static int append_bind_mounts(MountEntry **p, const BindMount *binds, size_t n) {
        size_t i;

        assert(p);

        for (i = 0; i < n; i++) {
                const BindMount *b = binds + i;

                *((*p)++) = (MountEntry) {
                        .path_const = b->destination,
                        .mode = b->recursive ? BIND_MOUNT_RECURSIVE : BIND_MOUNT,
                        .read_only = b->read_only,
                        .nosuid = b->nosuid,
                        .source_const = b->source,
                        .ignore = b->ignore_enoent,
                };
        }

        return 0;
}

static int append_tmpfs_mounts(MountEntry **p, const TemporaryFileSystem *tmpfs, size_t n) {
        size_t i;
        int r;

        assert(p);

        for (i = 0; i < n; i++) {
                const TemporaryFileSystem *t = tmpfs + i;
                _cleanup_free_ char *o = NULL, *str = NULL;
                unsigned long flags;
                bool ro = false;

                if (!path_is_absolute(t->path))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Path is not absolute: %s",
                                               t->path);

                str = strjoin("mode=0755,", t->options);
                if (!str)
                        return -ENOMEM;

                r = mount_option_mangle(str, MS_NODEV|MS_STRICTATIME, &flags, &o);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse mount option '%s': %m", str);

                ro = flags & MS_RDONLY;
                if (ro)
                        flags ^= MS_RDONLY;

                *((*p)++) = (MountEntry) {
                        .path_const = t->path,
                        .mode = TMPFS,
                        .read_only = ro,
                        .options_malloc = TAKE_PTR(o),
                        .flags = flags,
                };
        }

        return 0;
}

static int append_static_mounts(MountEntry **p, const MountEntry *mounts, size_t n, bool ignore_protect) {
        size_t i;

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

static int mount_path_compare(const MountEntry *a, const MountEntry *b) {
        int d;

        /* If the paths are not equal, then order prefixes first */
        d = path_compare(mount_entry_path(a), mount_entry_path(b));
        if (d != 0)
                return d;

        /* If the paths are equal, check the mode */
        return CMP((int) a->mode, (int) b->mode);
}

static int prefix_where_needed(MountEntry *m, size_t n, const char *root_directory) {
        size_t i;

        /* Prefixes all paths in the bind mount table with the root directory if the entry needs that. */

        for (i = 0; i < n; i++) {
                char *s;

                if (m[i].has_prefix)
                        continue;

                s = path_join(root_directory, mount_entry_path(m+i));
                if (!s)
                        return -ENOMEM;

                free_and_replace(m[i].path_malloc, s);
                m[i].has_prefix = true;
        }

        return 0;
}

static void drop_duplicates(MountEntry *m, size_t *n) {
        MountEntry *f, *t, *previous;

        assert(m);
        assert(n);

        /* Drops duplicate entries. Expects that the array is properly ordered already. */

        for (f = m, t = m, previous = NULL; f < m + *n; f++) {

                /* The first one wins (which is the one with the more restrictive mode), see mount_path_compare()
                 * above. Note that we only drop duplicates that haven't been mounted yet. */
                if (previous &&
                    path_equal(mount_entry_path(f), mount_entry_path(previous)) &&
                    !f->applied && !previous->applied) {
                        log_debug("%s (%s) is duplicate.", mount_entry_path(f), mount_mode_to_string(f->mode));
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

static void drop_inaccessible(MountEntry *m, size_t *n) {
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

static void drop_nop(MountEntry *m, size_t *n) {
        MountEntry *f, *t;

        assert(m);
        assert(n);

        /* Drops all entries which have an immediate parent that has the same type, as they are redundant. Assumes the
         * list is ordered by prefixes. */

        for (f = m, t = m; f < m + *n; f++) {

                /* Only suppress such subtrees for READONLY, READWRITE and READWRITE_IMPLICIT entries */
                if (IN_SET(f->mode, READONLY, READWRITE, READWRITE_IMPLICIT)) {
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
                                log_debug("%s (%s) is made redundant by %s (%s)",
                                          mount_entry_path(f), mount_mode_to_string(f->mode),
                                          mount_entry_path(p), mount_mode_to_string(p->mode));
                                mount_entry_done(f);
                                continue;
                        }
                }

                *t = *f;
                t++;
        }

        *n = t - m;
}

static void drop_outside_root(const char *root_directory, MountEntry *m, size_t *n) {
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

static int clone_device_node(
                const char *d,
                const char *temporary_mount,
                bool *make_devnode) {

        _cleanup_free_ char *sl = NULL;
        const char *dn, *bn, *t;
        struct stat st;
        int r;

        if (stat(d, &st) < 0) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "Device node '%s' to clone does not exist, ignoring.", d);
                        return -ENXIO;
                }

                return log_debug_errno(errno, "Failed to stat() device node '%s' to clone, ignoring: %m", d);
        }

        if (!S_ISBLK(st.st_mode) &&
            !S_ISCHR(st.st_mode))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Device node '%s' to clone is not a device node, ignoring.",
                                       d);

        dn = strjoina(temporary_mount, d);

        /* First, try to create device node properly */
        if (*make_devnode) {
                mac_selinux_create_file_prepare(d, st.st_mode);
                r = mknod(dn, st.st_mode, st.st_rdev);
                mac_selinux_create_file_clear();
                if (r >= 0)
                        goto add_symlink;
                if (errno != EPERM)
                        return log_debug_errno(errno, "mknod failed for %s: %m", d);

                /* This didn't work, let's not try this again for the next iterations. */
                *make_devnode = false;
        }

        /* We're about to fallback to bind-mounting the device
         * node. So create a dummy bind-mount target. */
        mac_selinux_create_file_prepare(d, 0);
        r = mknod(dn, S_IFREG, 0);
        mac_selinux_create_file_clear();
        if (r < 0 && errno != EEXIST)
                return log_debug_errno(errno, "mknod() fallback failed for '%s': %m", d);

        /* Fallback to bind-mounting:
         * The assumption here is that all used device nodes carry standard
         * properties. Specifically, the devices nodes we bind-mount should
         * either be owned by root:root or root:tty (e.g. /dev/tty, /dev/ptmx)
         * and should not carry ACLs. */
        if (mount(d, dn, NULL, MS_BIND, NULL) < 0)
                return log_debug_errno(errno, "Bind mounting failed for '%s': %m", d);

add_symlink:
        bn = path_startswith(d, "/dev/");
        if (!bn)
                return 0;

        /* Create symlinks like /dev/char/1:9 → ../urandom */
        if (asprintf(&sl, "%s/dev/%s/%u:%u", temporary_mount, S_ISCHR(st.st_mode) ? "char" : "block", major(st.st_rdev), minor(st.st_rdev)) < 0)
                return log_oom();

        (void) mkdir_parents(sl, 0755);

        t = strjoina("../", bn);

        if (symlink(t, sl) < 0)
                log_debug_errno(errno, "Failed to symlink '%s' to '%s', ignoring: %m", t, sl);

        return 0;
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
        bool can_mknod = true;
        _cleanup_umask_ mode_t u;
        int r;

        assert(m);

        u = umask(0000);

        if (!mkdtemp(temporary_mount))
                return log_debug_errno(errno, "Failed to create temporary directory '%s': %m", temporary_mount);

        dev = strjoina(temporary_mount, "/dev");
        (void) mkdir(dev, 0755);
        if (mount("tmpfs", dev, "tmpfs", DEV_MOUNT_OPTIONS, "mode=755") < 0) {
                r = log_debug_errno(errno, "Failed to mount tmpfs on '%s': %m", dev);
                goto fail;
        }

        devpts = strjoina(temporary_mount, "/dev/pts");
        (void) mkdir(devpts, 0755);
        if (mount("/dev/pts", devpts, NULL, MS_BIND, NULL) < 0) {
                r = log_debug_errno(errno, "Failed to bind mount /dev/pts on '%s': %m", devpts);
                goto fail;
        }

        /* /dev/ptmx can either be a device node or a symlink to /dev/pts/ptmx.
         * When /dev/ptmx a device node, /dev/pts/ptmx has 000 permissions making it inaccessible.
         * Thus, in that case make a clone.
         * In nspawn and other containers it will be a symlink, in that case make it a symlink. */
        r = is_symlink("/dev/ptmx");
        if (r < 0) {
                log_debug_errno(r, "Failed to detect whether /dev/ptmx is a symlink or not: %m");
                goto fail;
        } else if (r > 0) {
                devptmx = strjoina(temporary_mount, "/dev/ptmx");
                if (symlink("pts/ptmx", devptmx) < 0) {
                        r = log_debug_errno(errno, "Failed to create a symlink '%s' to pts/ptmx: %m", devptmx);
                        goto fail;
                }
        } else {
                r = clone_device_node("/dev/ptmx", temporary_mount, &can_mknod);
                if (r < 0)
                        goto fail;
        }

        devshm = strjoina(temporary_mount, "/dev/shm");
        (void) mkdir(devshm, 0755);
        r = mount("/dev/shm", devshm, NULL, MS_BIND, NULL);
        if (r < 0) {
                r = log_debug_errno(errno, "Failed to bind mount /dev/shm on '%s': %m", devshm);
                goto fail;
        }

        devmqueue = strjoina(temporary_mount, "/dev/mqueue");
        (void) mkdir(devmqueue, 0755);
        if (mount("/dev/mqueue", devmqueue, NULL, MS_BIND, NULL) < 0)
                log_debug_errno(errno, "Failed to bind mount /dev/mqueue on '%s', ignoring: %m", devmqueue);

        devhugepages = strjoina(temporary_mount, "/dev/hugepages");
        (void) mkdir(devhugepages, 0755);
        if (mount("/dev/hugepages", devhugepages, NULL, MS_BIND, NULL) < 0)
                log_debug_errno(errno, "Failed to bind mount /dev/hugepages on '%s', ignoring: %m", devhugepages);

        devlog = strjoina(temporary_mount, "/dev/log");
        if (symlink("/run/systemd/journal/dev-log", devlog) < 0)
                log_debug_errno(errno, "Failed to create a symlink '%s' to /run/systemd/journal/dev-log, ignoring: %m", devlog);

        NULSTR_FOREACH(d, devnodes) {
                r = clone_device_node(d, temporary_mount, &can_mknod);
                /* ENXIO means the the *source* is not a device file, skip creation in that case */
                if (r < 0 && r != -ENXIO)
                        goto fail;
        }

        r = dev_setup(temporary_mount, UID_INVALID, GID_INVALID);
        if (r < 0)
                log_debug_errno(r, "Failed to setup basic device tree at '%s', ignoring: %m", temporary_mount);

        /* Create the /dev directory if missing. It is more likely to be
         * missing when the service is started with RootDirectory. This is
         * consistent with mount units creating the mount points when missing.
         */
        (void) mkdir_p_label(mount_entry_path(m), 0755);

        /* Unmount everything in old /dev */
        r = umount_recursive(mount_entry_path(m), 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below '%s', ignoring: %m", mount_entry_path(m));

        if (mount(dev, mount_entry_path(m), NULL, MS_MOVE, NULL) < 0) {
                r = log_debug_errno(errno, "Failed to move mount point '%s' to '%s': %m", dev, mount_entry_path(m));
                goto fail;
        }

        (void) rmdir(dev);
        (void) rmdir(temporary_mount);

        return 0;

fail:
        if (devpts)
                (void) umount(devpts);

        if (devshm)
                (void) umount(devshm);

        if (devhugepages)
                (void) umount(devhugepages);

        if (devmqueue)
                (void) umount(devmqueue);

        (void) umount(dev);
        (void) rmdir(dev);
        (void) rmdir(temporary_mount);

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

static int follow_symlink(
                const char *root_directory,
                MountEntry *m) {

        _cleanup_free_ char *target = NULL;
        int r;

        /* Let's chase symlinks, but only one step at a time. That's because depending where the symlink points we
         * might need to change the order in which we mount stuff. Hence: let's normalize piecemeal, and do one step at
         * a time by specifying CHASE_STEP. This function returns 0 if we resolved one step, and > 0 if we reached the
         * end and already have a fully normalized name. */

        r = chase_symlinks(mount_entry_path(m), root_directory, CHASE_STEP|CHASE_NONEXISTENT, &target);
        if (r < 0)
                return log_debug_errno(r, "Failed to chase symlinks '%s': %m", mount_entry_path(m));
        if (r > 0) /* Reached the end, nothing more to resolve */
                return 1;

        if (m->n_followed >= CHASE_SYMLINKS_MAX) /* put a boundary on things */
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Symlink loop on '%s'.",
                                       mount_entry_path(m));

        log_debug("Followed mount entry path symlink %s → %s.", mount_entry_path(m), target);

        free_and_replace(m->path_malloc, target);
        m->has_prefix = true;

        m->n_followed ++;

        return 0;
}

static int apply_mount(
                const char *root_directory,
                MountEntry *m) {

        bool rbind = true, make = false;
        const char *what;
        int r;

        assert(m);

        log_debug("Applying namespace mount on %s", mount_entry_path(m));

        switch (m->mode) {

        case INACCESSIBLE: {
                struct stat target;

                /* First, get rid of everything that is below if there
                 * is anything... Then, overmount it with an
                 * inaccessible path. */
                (void) umount_recursive(mount_entry_path(m), 0);

                if (lstat(mount_entry_path(m), &target) < 0) {
                        if (errno == ENOENT && m->ignore)
                                return 0;

                        return log_debug_errno(errno, "Failed to lstat() %s to determine what to mount over it: %m", mount_entry_path(m));
                }

                what = mode_to_inaccessible_node(target.st_mode);
                if (!what)
                        return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                               "File type not supported for inaccessible mounts. Note that symlinks are not allowed");
                break;
        }

        case READONLY:
        case READWRITE:
        case READWRITE_IMPLICIT:
                r = path_is_mount_point(mount_entry_path(m), root_directory, 0);
                if (r == -ENOENT && m->ignore)
                        return 0;
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
        case BIND_MOUNT_RECURSIVE: {
                _cleanup_free_ char *chased = NULL;

                /* Since mount() will always follow symlinks we chase the symlinks on our own first. Note that bind
                 * mount source paths are always relative to the host root, hence we pass NULL as root directory to
                 * chase_symlinks() here. */

                r = chase_symlinks(mount_entry_source(m), NULL, CHASE_TRAIL_SLASH, &chased);
                if (r == -ENOENT && m->ignore) {
                        log_debug_errno(r, "Path %s does not exist, ignoring.", mount_entry_source(m));
                        return 0;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to follow symlinks on %s: %m", mount_entry_source(m));

                log_debug("Followed source symlinks %s → %s.", mount_entry_source(m), chased);

                free_and_replace(m->source_malloc, chased);

                what = mount_entry_source(m);
                make = true;
                break;
        }

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

                        if (stat(what, &st) < 0)
                                log_debug_errno(errno, "Mount point source '%s' is not accessible: %m", what);
                        else {
                                int q;

                                (void) mkdir_parents(mount_entry_path(m), 0755);

                                if (S_ISDIR(st.st_mode))
                                        q = mkdir(mount_entry_path(m), 0755) < 0 ? -errno : 0;
                                else
                                        q = touch(mount_entry_path(m));

                                if (q < 0)
                                        log_debug_errno(q, "Failed to create destination mount point node '%s': %m", mount_entry_path(m));
                                else
                                        try_again = true;
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

/* Change per-mount flags on an existing mount */
static int bind_remount_one(const char *path, unsigned long orig_flags, unsigned long new_flags, unsigned long flags_mask) {
        if (mount(NULL, path, NULL, (orig_flags & ~flags_mask) | MS_REMOUNT | MS_BIND | new_flags, NULL) < 0)
                return -errno;

        return 0;
}

static int make_read_only(const MountEntry *m, char **blacklist, FILE *proc_self_mountinfo) {
        unsigned long new_flags = 0, flags_mask = 0;
        bool submounts = false;
        int r = 0;

        assert(m);
        assert(proc_self_mountinfo);

        if (mount_entry_read_only(m) || m->mode == PRIVATE_DEV) {
                new_flags |= MS_RDONLY;
                flags_mask |= MS_RDONLY;
        }

        if (m->nosuid) {
                new_flags |= MS_NOSUID;
                flags_mask |= MS_NOSUID;
        }

        if (flags_mask == 0) /* No Change? */
                return 0;

        /* We generally apply these changes recursively, except for /dev, and the cases we know there's
         * nothing further down.  Set /dev readonly, but not submounts like /dev/shm. Also, we only set the
         * per-mount read-only flag.  We can't set it on the superblock, if we are inside a user namespace
         * and running Linux <= 4.17. */
        submounts =
                mount_entry_read_only(m) &&
                !IN_SET(m->mode, EMPTY_DIR, TMPFS);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, blacklist, proc_self_mountinfo);
        else
                r = bind_remount_one(mount_entry_path(m), m->flags, new_flags, flags_mask);

        /* Not that we only turn on the MS_RDONLY flag here, we never turn it off. Something that was marked
         * read-only already stays this way. This improves compatibility with container managers, where we
         * won't attempt to undo read-only mounts already applied. */

        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

static bool namespace_info_mount_apivfs(const NamespaceInfo *ns_info) {
        assert(ns_info);

        /*
         * ProtectControlGroups= and ProtectKernelTunables= imply MountAPIVFS=,
         * since to protect the API VFS mounts, they need to be around in the
         * first place...
         */

        return ns_info->mount_apivfs ||
                ns_info->protect_control_groups ||
                ns_info->protect_kernel_tunables;
}

static size_t namespace_calculate_mounts(
                const NamespaceInfo *ns_info,
                char** read_write_paths,
                char** read_only_paths,
                char** inaccessible_paths,
                char** empty_directories,
                size_t n_bind_mounts,
                size_t n_temporary_filesystems,
                const char* tmp_dir,
                const char* var_tmp_dir,
                ProtectHome protect_home,
                ProtectSystem protect_system) {

        size_t protect_home_cnt;
        size_t protect_system_cnt =
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
                (ns_info->protect_hostname ? 2 : 0) +
                (namespace_info_mount_apivfs(ns_info) ? ELEMENTSOF(apivfs_table) : 0);
}

static void normalize_mounts(const char *root_directory, MountEntry *mounts, size_t *n_mounts) {
        assert(root_directory);
        assert(n_mounts);
        assert(mounts || *n_mounts == 0);

        typesafe_qsort(mounts, *n_mounts, mount_path_compare);

        drop_duplicates(mounts, n_mounts);
        drop_outside_root(root_directory, mounts, n_mounts);
        drop_inaccessible(mounts, n_mounts);
        drop_nop(mounts, n_mounts);
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
                size_t n_bind_mounts,
                const TemporaryFileSystem *temporary_filesystems,
                size_t n_temporary_filesystems,
                const char* tmp_dir,
                const char* var_tmp_dir,
                ProtectHome protect_home,
                ProtectSystem protect_system,
                unsigned long mount_flags,
                DissectImageFlags dissect_image_flags,
                char **error_path) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(decrypted_image_unrefp) DecryptedImage *decrypted_image = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_free_ void *root_hash = NULL;
        MountEntry *m = NULL, *mounts = NULL;
        size_t n_mounts, root_hash_size = 0;
        bool require_prefix = false;
        const char *root;
        int r = 0;

        assert(ns_info);

        if (mount_flags == 0)
                mount_flags = MS_SHARED;

        if (root_image) {
                dissect_image_flags |= DISSECT_IMAGE_REQUIRE_ROOT;

                if (protect_system == PROTECT_SYSTEM_STRICT &&
                    protect_home != PROTECT_HOME_NO &&
                    strv_isempty(read_write_paths))
                        dissect_image_flags |= DISSECT_IMAGE_READ_ONLY;

                r = loop_device_make_by_path(root_image,
                                             dissect_image_flags & DISSECT_IMAGE_READ_ONLY ? O_RDONLY : O_RDWR,
                                             &loop_device);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create loop device for root image: %m");

                r = root_hash_load(root_image, &root_hash, &root_hash_size);
                if (r < 0)
                        return log_debug_errno(r, "Failed to load root hash: %m");

                r = dissect_image(loop_device->fd, root_hash, root_hash_size, dissect_image_flags, &dissected_image);
                if (r < 0)
                        return log_debug_errno(r, "Failed to dissect image: %m");

                r = dissected_image_decrypt(dissected_image, NULL, root_hash, root_hash_size, dissect_image_flags, &decrypted_image);
                if (r < 0)
                        return log_debug_errno(r, "Failed to decrypt dissected image: %m");
        }

        if (root_directory)
                root = root_directory;
        else {
                /* Always create the mount namespace in a temporary directory, instead of operating
                 * directly in the root. The temporary directory prevents any mounts from being
                 * potentially obscured my other mounts we already applied.
                 * We use the same mount point for all images, which is safe, since they all live
                 * in their own namespaces after all, and hence won't see each other. */

                root = "/run/systemd/unit-root";
                (void) mkdir_label(root, 0700);
                require_prefix = true;
        }

        n_mounts = namespace_calculate_mounts(
                        ns_info,
                        read_write_paths,
                        read_only_paths,
                        inaccessible_paths,
                        empty_directories,
                        n_bind_mounts,
                        n_temporary_filesystems,
                        tmp_dir, var_tmp_dir,
                        protect_home, protect_system);

        if (n_mounts > 0) {
                m = mounts = new0(MountEntry, n_mounts);
                if (!mounts)
                        return -ENOMEM;

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
                                .flags = DEV_MOUNT_OPTIONS,
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

                if (namespace_info_mount_apivfs(ns_info)) {
                        r = append_static_mounts(&m, apivfs_table, ELEMENTSOF(apivfs_table), ns_info->ignore_protect_paths);
                        if (r < 0)
                                goto finish;
                }

                if (ns_info->protect_hostname) {
                        *(m++) = (MountEntry) {
                                .path_const = "/proc/sys/kernel/hostname",
                                .mode = READONLY,
                        };
                        *(m++) = (MountEntry) {
                                .path_const = "/proc/sys/kernel/domainname",
                                .mode = READONLY,
                        };
                }

                assert(mounts + n_mounts == m);

                /* Prepend the root directory where that's necessary */
                r = prefix_where_needed(mounts, n_mounts, root);
                if (r < 0)
                        goto finish;

                normalize_mounts(root, mounts, &n_mounts);
        }

        /* All above is just preparation, figuring out what to do. Let's now actually start doing something. */

        if (unshare(CLONE_NEWNS) < 0) {
                r = log_debug_errno(errno, "Failed to unshare the mount namespace: %m");
                if (IN_SET(r, -EACCES, -EPERM, -EOPNOTSUPP, -ENOSYS))
                        /* If the kernel doesn't support namespaces, or when there's a MAC or seccomp filter in place
                         * that doesn't allow us to create namespaces (or a missing cap), then propagate a recognizable
                         * error back, which the caller can use to detect this case (and only this) and optionally
                         * continue without namespacing applied. */
                        r = -ENOANO;

                goto finish;
        }

        /* Remount / as SLAVE so that nothing now mounted in the namespace
         * shows up in the parent */
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0) {
                r = log_debug_errno(errno, "Failed to remount '/' as SLAVE: %m");
                goto finish;
        }

        if (root_image) {
                /* A root image is specified, mount it to the right place */
                r = dissected_image_mount(dissected_image, root, UID_INVALID, dissect_image_flags);
                if (r < 0) {
                        log_debug_errno(r, "Failed to mount root image: %m");
                        goto finish;
                }

                if (decrypted_image) {
                        r = decrypted_image_relinquish(decrypted_image);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to relinquish decrypted image: %m");
                                goto finish;
                        }
                }

                loop_device_relinquish(loop_device);

        } else if (root_directory) {

                /* A root directory is specified. Turn its directory into bind mount, if it isn't one yet. */
                r = path_is_mount_point(root, NULL, AT_SYMLINK_FOLLOW);
                if (r < 0) {
                        log_debug_errno(r, "Failed to detect that %s is a mount point or not: %m", root);
                        goto finish;
                }
                if (r == 0) {
                        if (mount(root, root, NULL, MS_BIND|MS_REC, NULL) < 0) {
                                r = log_debug_errno(errno, "Failed to bind mount '%s': %m", root);
                                goto finish;
                        }
                }

        } else {

                /* Let's mount the main root directory to the root directory to use */
                if (mount("/", root, NULL, MS_BIND|MS_REC, NULL) < 0) {
                        r = log_debug_errno(errno, "Failed to bind mount '/' on '%s': %m", root);
                        goto finish;
                }
        }

        /* Try to set up the new root directory before mounting anything else there. */
        if (root_image || root_directory)
                (void) base_filesystem_create(root, UID_INVALID, GID_INVALID);

        if (n_mounts > 0) {
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
                _cleanup_free_ char **blacklist = NULL;
                size_t j;

                /* Open /proc/self/mountinfo now as it may become unavailable if we mount anything on top of /proc.
                 * For example, this is the case with the option: 'InaccessiblePaths=/proc' */
                proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!proc_self_mountinfo) {
                        r = log_debug_errno(errno, "Failed to open /proc/self/mountinfo: %m");
                        if (error_path)
                                *error_path = strdup("/proc/self/mountinfo");
                        goto finish;
                }

                /* First round, establish all mounts we need */
                for (;;) {
                        bool again = false;

                        for (m = mounts; m < mounts + n_mounts; ++m) {

                                if (m->applied)
                                        continue;

                                r = follow_symlink(root, m);
                                if (r < 0) {
                                        if (error_path && mount_entry_path(m))
                                                *error_path = strdup(mount_entry_path(m));
                                        goto finish;
                                }
                                if (r == 0) {
                                        /* We hit a symlinked mount point. The entry got rewritten and might point to a
                                         * very different place now. Let's normalize the changed list, and start from
                                         * the beginning. After all to mount the entry at the new location we might
                                         * need some other mounts first */
                                        again = true;
                                        break;
                                }

                                r = apply_mount(root, m);
                                if (r < 0) {
                                        if (error_path && mount_entry_path(m))
                                                *error_path = strdup(mount_entry_path(m));
                                        goto finish;
                                }

                                m->applied = true;
                        }

                        if (!again)
                                break;

                        normalize_mounts(root, mounts, &n_mounts);
                }

                /* Create a blacklist we can pass to bind_mount_recursive() */
                blacklist = new(char*, n_mounts+1);
                if (!blacklist) {
                        r = -ENOMEM;
                        goto finish;
                }
                for (j = 0; j < n_mounts; j++)
                        blacklist[j] = (char*) mount_entry_path(mounts+j);
                blacklist[j] = NULL;

                /* Second round, flip the ro bits if necessary. */
                for (m = mounts; m < mounts + n_mounts; ++m) {
                        r = make_read_only(m, blacklist, proc_self_mountinfo);
                        if (r < 0) {
                                if (error_path && mount_entry_path(m))
                                        *error_path = strdup(mount_entry_path(m));
                                goto finish;
                        }
                }
        }

        /* MS_MOVE does not work on MS_SHARED so the remount MS_SHARED will be done later */
        r = mount_move_root(root);
        if (r < 0) {
                log_debug_errno(r, "Failed to mount root with MS_MOVE: %m");
                goto finish;
        }

        /* Remount / as the desired mode. Note that this will not
         * reestablish propagation from our side to the host, since
         * what's disconnected is disconnected. */
        if (mount(NULL, "/", NULL, mount_flags | MS_REC, NULL) < 0) {
                r = log_debug_errno(errno, "Failed to remount '/' with desired mount flags: %m");
                goto finish;
        }

        r = 0;

finish:
        for (m = mounts; m < mounts + n_mounts; m++)
                mount_entry_done(m);

        free(mounts);

        return r;
}

void bind_mount_free_many(BindMount *b, size_t n) {
        size_t i;

        assert(b || n == 0);

        for (i = 0; i < n; i++) {
                free(b[i].source);
                free(b[i].destination);
        }

        free(b);
}

int bind_mount_add(BindMount **b, size_t *n, const BindMount *item) {
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
                .source = TAKE_PTR(s),
                .destination = TAKE_PTR(d),
                .read_only = item->read_only,
                .nosuid = item->nosuid,
                .recursive = item->recursive,
                .ignore_enoent = item->ignore_enoent,
        };

        return 0;
}

void temporary_filesystem_free_many(TemporaryFileSystem *t, size_t n) {
        size_t i;

        assert(t || n == 0);

        for (i = 0; i < n; i++) {
                free(t[i].path);
                free(t[i].options);
        }

        free(t);
}

int temporary_filesystem_add(
                TemporaryFileSystem **t,
                size_t *n,
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
                .path = TAKE_PTR(p),
                .options = TAKE_PTR(o),
        };

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

        *path = TAKE_PTR(x);

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
                (void) rmdir(t);
                (void) rmdir(a);

                free(a);
                return r;
        }

        *tmp_dir = a;
        *var_tmp_dir = b;

        return 0;
}

int setup_netns(const int netns_storage_socket[static 2]) {
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
                /* Nothing stored yet, so let's create a new namespace. */

                if (unshare(CLONE_NEWNET) < 0) {
                        r = -errno;
                        goto fail;
                }

                (void) loopback_setup();

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

int open_netns_path(const int netns_storage_socket[static 2], const char *path) {
        _cleanup_close_ int netns = -1;
        int q, r;

        assert(netns_storage_socket);
        assert(netns_storage_socket[0] >= 0);
        assert(netns_storage_socket[1] >= 0);
        assert(path);

        /* If the storage socket doesn't contain a netns fd yet, open one via the file system and store it in
         * it. This is supposed to be called ahead of time, i.e. before setup_netns() which will allocate a
         * new anonymous netns if needed. */

        if (lockf(netns_storage_socket[0], F_LOCK, 0) < 0)
                return -errno;

        netns = receive_one_fd(netns_storage_socket[0], MSG_DONTWAIT);
        if (netns == -EAGAIN) {
                /* Nothing stored yet. Open the file from the file system. */

                netns = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netns < 0) {
                        r = -errno;
                        goto fail;
                }

                r = fd_is_network_ns(netns);
                if (r == 0) { /* Not a netns? Refuse early. */
                        r = -EINVAL;
                        goto fail;
                }
                if (r < 0 && r != -EUCLEAN) /* EUCLEAN: we don't know */
                        goto fail;

                r = 1;

        } else if (netns < 0) {
                r = netns;
                goto fail;
        } else
                r = 0; /* Already allocated */

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

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_home, ProtectHome, PROTECT_HOME_YES);

static const char *const protect_system_table[_PROTECT_SYSTEM_MAX] = {
        [PROTECT_SYSTEM_NO] = "no",
        [PROTECT_SYSTEM_YES] = "yes",
        [PROTECT_SYSTEM_FULL] = "full",
        [PROTECT_SYSTEM_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_system, ProtectSystem, PROTECT_SYSTEM_YES);

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
