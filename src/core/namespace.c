/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/loop.h>
#include <sched.h>
#include <stdio.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <unistd.h>
#if WANT_LINUX_FS_H
#include <linux/fs.h>
#endif

#include "alloc-util.h"
#include "base-filesystem.h"
#include "chase.h"
#include "dev-setup.h"
#include "devnum-util.h"
#include "env-util.h"
#include "escape.h"
#include "extension-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "label-util.h"
#include "list.h"
#include "lock-util.h"
#include "loop-util.h"
#include "loopback-setup.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "namespace.h"
#include "nsflags.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "selinux-util.h"
#include "socket-util.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"

#define DEV_MOUNT_OPTIONS (MS_NOSUID|MS_STRICTATIME|MS_NOEXEC)

typedef enum MountMode {
        /* This is ordered by priority! */
        MOUNT_INACCESSIBLE,
        MOUNT_OVERLAY,
        MOUNT_IMAGE,
        MOUNT_BIND,
        MOUNT_BIND_RECURSIVE,
        MOUNT_PRIVATE_TMP,
        MOUNT_PRIVATE_TMP_READ_ONLY,
        MOUNT_PRIVATE_DEV,
        MOUNT_BIND_DEV,
        MOUNT_EMPTY_DIR,
        MOUNT_PRIVATE_SYSFS,
        MOUNT_BIND_SYSFS,
        MOUNT_PROCFS,
        MOUNT_READ_ONLY,
        MOUNT_READ_WRITE,
        MOUNT_NOEXEC,
        MOUNT_EXEC,
        MOUNT_TMPFS,
        MOUNT_RUN,
        MOUNT_EXTENSION_DIRECTORY, /* Bind-mounted outside the root directory, and used by subsequent mounts */
        MOUNT_EXTENSION_IMAGE,     /* Mounted outside the root directory, and used by subsequent mounts */
        MOUNT_MQUEUEFS,
        MOUNT_READ_WRITE_IMPLICIT, /* Should have the lowest priority. */
        _MOUNT_MODE_MAX,
        _MOUNT_MODE_INVALID = -EINVAL,
} MountMode;

typedef enum MountEntryState {
        MOUNT_PENDING,
        MOUNT_APPLIED,
        MOUNT_SKIPPED,
        _MOUNT_ENTRY_STATE_MAX,
        _MOUNT_ENTRY_STATE_INVALID = -EINVAL,
} MountEntryState;

typedef struct MountEntry {
        const char *path_const;   /* Memory allocated on stack or static */
        MountMode mode;
        bool ignore:1;            /* Ignore if path does not exist? */
        bool has_prefix:1;        /* Already is prefixed by the root dir? */
        bool read_only:1;         /* Shall this mount point be read-only? */
        bool nosuid:1;            /* Shall set MS_NOSUID on the mount itself */
        bool noexec:1;            /* Shall set MS_NOEXEC on the mount itself */
        bool exec:1;              /* Shall clear MS_NOEXEC on the mount itself */
        MountEntryState state;    /* Whether it was already processed or skipped */
        char *path_malloc;        /* Use this instead of 'path_const' if we had to allocate memory */
        const char *unprefixed_path_const; /* If the path was amended with a prefix, these will save the original */
        char *unprefixed_path_malloc;
        const char *source_const; /* The source path, for bind mounts or images */
        char *source_malloc;
        const char *options_const;/* Mount options for tmpfs */
        char *options_malloc;
        unsigned long flags;      /* Mount flags used by EMPTY_DIR and TMPFS. Do not include MS_RDONLY here, but please use read_only. */
        unsigned n_followed;
        LIST_HEAD(MountOptions, image_options_const);
        char **overlay_layers;
} MountEntry;

typedef struct MountList {
        MountEntry *mounts;
        size_t n_mounts;
} MountList;

/* If MountAPIVFS= is used, let's mount /sys, /proc, /dev and /run into the it, but only as a fallback if the user hasn't mounted
 * something there already. These mounts are hence overridden by any other explicitly configured mounts. */
static const MountEntry apivfs_table[] = {
        { "/proc",               MOUNT_PROCFS,       false },
        { "/dev",                MOUNT_BIND_DEV,     false },
        { "/sys",                MOUNT_BIND_SYSFS,   false },
        { "/run",                MOUNT_RUN,          false, .options_const = "mode=0755" TMPFS_LIMITS_RUN, .flags = MS_NOSUID|MS_NODEV|MS_STRICTATIME },
};

/* ProtectKernelTunables= option and the related filesystem APIs */
static const MountEntry protect_kernel_tunables_proc_table[] = {
        { "/proc/acpi",          MOUNT_READ_ONLY,           true  },
        { "/proc/apm",           MOUNT_READ_ONLY,           true  }, /* Obsolete API, there's no point in permitting access to this, ever */
        { "/proc/asound",        MOUNT_READ_ONLY,           true  },
        { "/proc/bus",           MOUNT_READ_ONLY,           true  },
        { "/proc/fs",            MOUNT_READ_ONLY,           true  },
        { "/proc/irq",           MOUNT_READ_ONLY,           true  },
        { "/proc/kallsyms",      MOUNT_INACCESSIBLE,        true  },
        { "/proc/kcore",         MOUNT_INACCESSIBLE,        true  },
        { "/proc/latency_stats", MOUNT_READ_ONLY,           true  },
        { "/proc/mtrr",          MOUNT_READ_ONLY,           true  },
        { "/proc/scsi",          MOUNT_READ_ONLY,           true  },
        { "/proc/sys",           MOUNT_READ_ONLY,           true  },
        { "/proc/sysrq-trigger", MOUNT_READ_ONLY,           true  },
        { "/proc/timer_stats",   MOUNT_READ_ONLY,           true  },
};

static const MountEntry protect_kernel_tunables_sys_table[] = {
        { "/sys",                MOUNT_READ_ONLY,           false },
        { "/sys/fs/bpf",         MOUNT_READ_ONLY,           true  },
        { "/sys/fs/cgroup",      MOUNT_READ_WRITE_IMPLICIT, false }, /* READ_ONLY is set by ProtectControlGroups= option */
        { "/sys/fs/selinux",     MOUNT_READ_WRITE_IMPLICIT, true  },
        { "/sys/kernel/debug",   MOUNT_READ_ONLY,           true  },
        { "/sys/kernel/tracing", MOUNT_READ_ONLY,           true  },
};

/* ProtectKernelModules= option */
static const MountEntry protect_kernel_modules_table[] = {
        { "/usr/lib/modules",    MOUNT_INACCESSIBLE, true  },
};

/* ProtectKernelLogs= option */
static const MountEntry protect_kernel_logs_proc_table[] = {
        { "/proc/kmsg",          MOUNT_INACCESSIBLE, true },
};

static const MountEntry protect_kernel_logs_dev_table[] = {
        { "/dev/kmsg",           MOUNT_INACCESSIBLE, true },
};

/*
 * ProtectHome=read-only table, protect $HOME and $XDG_RUNTIME_DIR and rest of
 * system should be protected by ProtectSystem=
 */
static const MountEntry protect_home_read_only_table[] = {
        { "/home",               MOUNT_READ_ONLY,     true  },
        { "/run/user",           MOUNT_READ_ONLY,     true  },
        { "/root",               MOUNT_READ_ONLY,     true  },
};

/* ProtectHome=tmpfs table */
static const MountEntry protect_home_tmpfs_table[] = {
        { "/home",               MOUNT_TMPFS,        true, .read_only = true, .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST, .flags = MS_NODEV|MS_STRICTATIME },
        { "/run/user",           MOUNT_TMPFS,        true, .read_only = true, .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST, .flags = MS_NODEV|MS_STRICTATIME },
        { "/root",               MOUNT_TMPFS,        true, .read_only = true, .options_const = "mode=0700" TMPFS_LIMITS_EMPTY_OR_ALMOST, .flags = MS_NODEV|MS_STRICTATIME },
};

/* ProtectHome=yes table */
static const MountEntry protect_home_yes_table[] = {
        { "/home",               MOUNT_INACCESSIBLE, true  },
        { "/run/user",           MOUNT_INACCESSIBLE, true  },
        { "/root",               MOUNT_INACCESSIBLE, true  },
};

/* ProtectSystem=yes table */
static const MountEntry protect_system_yes_table[] = {
        { "/usr",                MOUNT_READ_ONLY,     false },
        { "/boot",               MOUNT_READ_ONLY,     true  },
        { "/efi",                MOUNT_READ_ONLY,     true  },
};

/* ProtectSystem=full includes ProtectSystem=yes */
static const MountEntry protect_system_full_table[] = {
        { "/usr",                MOUNT_READ_ONLY,     false },
        { "/boot",               MOUNT_READ_ONLY,     true  },
        { "/efi",                MOUNT_READ_ONLY,     true  },
        { "/etc",                MOUNT_READ_ONLY,     false },
};

/* ProtectSystem=strict table. In this strict mode, we mount everything read-only, except for /proc, /dev,
 * /sys which are the kernel API VFS, which are left writable, but PrivateDevices= + ProtectKernelTunables=
 * protect those, and these options should be fully orthogonal.  (And of course /home and friends are also
 * left writable, as ProtectHome= shall manage those, orthogonally).
 */
static const MountEntry protect_system_strict_table[] = {
        { "/",                   MOUNT_READ_ONLY,          false },
        { "/proc",               MOUNT_READ_WRITE_IMPLICIT, false },      /* ProtectKernelTunables= */
        { "/sys",                MOUNT_READ_WRITE_IMPLICIT, false },      /* ProtectKernelTunables= */
        { "/dev",                MOUNT_READ_WRITE_IMPLICIT, false },      /* PrivateDevices= */
        { "/home",               MOUNT_READ_WRITE_IMPLICIT, true  },      /* ProtectHome= */
        { "/run/user",           MOUNT_READ_WRITE_IMPLICIT, true  },      /* ProtectHome= */
        { "/root",               MOUNT_READ_WRITE_IMPLICIT, true  },      /* ProtectHome= */
};

/* ProtectHostname=yes able */
static const MountEntry protect_hostname_table[] = {
        { "/proc/sys/kernel/hostname",   MOUNT_READ_ONLY, false },
        { "/proc/sys/kernel/domainname", MOUNT_READ_ONLY, false },
};

static const char * const mount_mode_table[_MOUNT_MODE_MAX] = {
        [MOUNT_INACCESSIBLE]          = "inaccessible",
        [MOUNT_OVERLAY]               = "overlay",
        [MOUNT_IMAGE]                 = "image",
        [MOUNT_BIND]                  = "bind",
        [MOUNT_BIND_RECURSIVE]        = "bind-recursive",
        [MOUNT_PRIVATE_TMP]           = "private-tmp",
        [MOUNT_PRIVATE_TMP_READ_ONLY] = "private-tmp-read-only",
        [MOUNT_PRIVATE_DEV]           = "private-dev",
        [MOUNT_BIND_DEV]              = "bind-dev",
        [MOUNT_EMPTY_DIR]             = "empty-dir",
        [MOUNT_PRIVATE_SYSFS]         = "private-sysfs",
        [MOUNT_BIND_SYSFS]            = "bind-sysfs",
        [MOUNT_PROCFS]                = "procfs",
        [MOUNT_READ_ONLY]             = "read-only",
        [MOUNT_READ_WRITE]            = "read-write",
        [MOUNT_NOEXEC]                = "noexec",
        [MOUNT_EXEC]                  = "exec",
        [MOUNT_TMPFS]                 = "tmpfs",
        [MOUNT_RUN]                   = "run",
        [MOUNT_EXTENSION_DIRECTORY]   = "extension-directory",
        [MOUNT_EXTENSION_IMAGE]       = "extension-image",
        [MOUNT_MQUEUEFS]              = "mqueuefs",
        [MOUNT_READ_WRITE_IMPLICIT]   = "read-write-implicit",
};

/* Helper struct for naming simplicity and reusability */
static const struct {
        const char *level_env;
        const char *level_env_print;
} image_class_info[_IMAGE_CLASS_MAX] = {
        [IMAGE_SYSEXT] = {
                .level_env = "SYSEXT_LEVEL",
                .level_env_print = " SYSEXT_LEVEL=",
        },
        [IMAGE_CONFEXT] = {
                .level_env = "CONFEXT_LEVEL",
                .level_env_print = " CONFEXT_LEVEL=",
        }
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(mount_mode, MountMode);

static const char *mount_entry_path(const MountEntry *p) {
        assert(p);

        /* Returns the path of this bind mount. If the malloc()-allocated ->path_buffer field is set we return that,
         * otherwise the stack/static ->path field is returned. */

        return p->path_malloc ?: p->path_const;
}

static const char *mount_entry_unprefixed_path(const MountEntry *p) {
        assert(p);

        /* Returns the unprefixed path (ie: before prefix_where_needed() ran), if any */

        return p->unprefixed_path_malloc ?: p->unprefixed_path_const ?: mount_entry_path(p);
}

static void mount_entry_consume_prefix(MountEntry *p, char *new_path) {
        assert(p);
        assert(p->path_malloc || p->path_const);
        assert(new_path);

        /* Saves current path in unprefixed_ variable, and takes over new_path */

        free_and_replace(p->unprefixed_path_malloc, p->path_malloc);
        /* If we didn't have a path on the heap, then it's a static one */
        if (!p->unprefixed_path_malloc)
                p->unprefixed_path_const = p->path_const;
        p->path_malloc = new_path;
        p->has_prefix = true;
}

static bool mount_entry_read_only(const MountEntry *p) {
        assert(p);

        return p->read_only || IN_SET(p->mode, MOUNT_READ_ONLY, MOUNT_INACCESSIBLE, MOUNT_PRIVATE_TMP_READ_ONLY);
}

static bool mount_entry_noexec(const MountEntry *p) {
        assert(p);

        return p->noexec || IN_SET(p->mode, MOUNT_NOEXEC, MOUNT_INACCESSIBLE, MOUNT_PRIVATE_SYSFS, MOUNT_BIND_SYSFS, MOUNT_PROCFS);
}

static bool mount_entry_exec(const MountEntry *p) {
        assert(p);

        return p->exec || p->mode == MOUNT_EXEC;
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
        p->unprefixed_path_malloc = mfree(p->unprefixed_path_malloc);
        p->source_malloc = mfree(p->source_malloc);
        p->options_malloc = mfree(p->options_malloc);
        p->overlay_layers = strv_free(p->overlay_layers);
}

static void mount_list_done(MountList *ml) {
        assert(ml);

        FOREACH_ARRAY(m, ml->mounts, ml->n_mounts)
                mount_entry_done(m);

        ml->mounts = mfree(ml->mounts);
        ml->n_mounts = 0;
}

static MountEntry *mount_list_extend(MountList *ml) {
        assert(ml);

        if (!GREEDY_REALLOC0(ml->mounts, ml->n_mounts+1))
                return NULL;

        return ml->mounts + ml->n_mounts++;
}

static int append_access_mounts(MountList *ml, char **strv, MountMode mode, bool forcibly_require_prefix) {
        assert(ml);

        /* Adds a list of user-supplied READ_WRITE/READ_WRITE_IMPLICIT/READ_ONLY/INACCESSIBLE entries */

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
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Path is not absolute: %s", e);

                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = e,
                        .mode = mode,
                        .ignore = ignore,
                        .has_prefix = !needs_prefix && !forcibly_require_prefix,
                };
        }

        return 0;
}

static int append_empty_dir_mounts(MountList *ml, char **strv) {
        assert(ml);

        /* Adds tmpfs mounts to provide readable but empty directories. This is primarily used to implement the
         * "/private/" boundary directories for DynamicUser=1. */

        STRV_FOREACH(i, strv) {
                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = *i,
                        .mode = MOUNT_EMPTY_DIR,
                        .ignore = false,
                        .read_only = true,
                        .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST,
                        .flags = MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
                };
        }

        return 0;
}

static int append_bind_mounts(MountList *ml, const BindMount *binds, size_t n) {
        assert(ml);
        assert(binds || n == 0);

        FOREACH_ARRAY(b, binds, n) {
                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = b->destination,
                        .mode = b->recursive ? MOUNT_BIND_RECURSIVE : MOUNT_BIND,
                        .read_only = b->read_only,
                        .nosuid = b->nosuid,
                        .source_const = b->source,
                        .ignore = b->ignore_enoent,
                };
        }

        return 0;
}

static int append_mount_images(MountList *ml, const MountImage *mount_images, size_t n) {
        assert(ml);
        assert(mount_images || n == 0);

        FOREACH_ARRAY(m, mount_images, n) {
                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = m->destination,
                        .mode = MOUNT_IMAGE,
                        .source_const = m->source,
                        .image_options_const = m->mount_options,
                        .ignore = m->ignore_enoent,
                };
        }

        return 0;
}

static int append_extensions(
                MountList *ml,
                const char *root,
                const char *extension_dir,
                char **hierarchies,
                const MountImage *mount_images,
                size_t n,
                char **extension_directories) {

        char ***overlays = NULL;
        size_t n_overlays = 0;
        int r;

        assert(ml);

        if (n == 0 && strv_isempty(extension_directories))
                return 0;

        assert(extension_dir);

        n_overlays = strv_length(hierarchies);
        if (n_overlays == 0)
                return 0;

        /* Prepare a list of overlays, that will have as each element a strv containing all the layers that
         * will later be concatenated as a lowerdir= parameter for the mount operation.
         * The overlays vector will have the same number of elements and will correspond to the
         * hierarchies vector, so they can be iterated upon together. */
        overlays = new0(char**, n_overlays);
        if (!overlays)
                return -ENOMEM;

        CLEANUP_ARRAY(overlays, n_overlays, strv_free_many);

        /* First, prepare a mount for each image, but these won't be visible to the unit, instead
         * they will be mounted in our propagate directory, and used as a source for the overlay. */
        for (size_t i = 0; i < n; i++) {
                _cleanup_free_ char *mount_point = NULL;
                const MountImage *m = mount_images + i;

                if (asprintf(&mount_point, "%s/%zu", extension_dir, i) < 0)
                        return -ENOMEM;

                for (size_t j = 0; hierarchies && hierarchies[j]; ++j) {
                        char *prefixed_hierarchy = path_join(mount_point, hierarchies[j]);
                        if (!prefixed_hierarchy)
                                return -ENOMEM;

                        r = strv_consume(&overlays[j], TAKE_PTR(prefixed_hierarchy));
                        if (r < 0)
                                return r;
                }

                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return -ENOMEM;

                *me = (MountEntry) {
                        .path_malloc = TAKE_PTR(mount_point),
                        .image_options_const = m->mount_options,
                        .ignore = m->ignore_enoent,
                        .source_const = m->source,
                        .mode = MOUNT_EXTENSION_IMAGE,
                        .has_prefix = true,
                };
        }

        /* Secondly, extend the lowerdir= parameters with each ExtensionDirectory.
         * Bind mount them in the same location as the ExtensionImages, so that we
         * can check that they are valid trees (extension-release.d). */
        STRV_FOREACH(extension_directory, extension_directories) {
                _cleanup_free_ char *mount_point = NULL, *source = NULL;
                const char *e = *extension_directory;
                bool ignore_enoent = false;

                /* Pick up the counter where the ExtensionImages left it. */
                if (asprintf(&mount_point, "%s/%zu", extension_dir, n++) < 0)
                        return -ENOMEM;

                /* Look for any prefixes */
                if (startswith(e, "-")) {
                        e++;
                        ignore_enoent = true;
                }
                /* Ignore this for now */
                if (startswith(e, "+"))
                        e++;

                source = strdup(e);
                if (!source)
                        return -ENOMEM;

                for (size_t j = 0; hierarchies && hierarchies[j]; ++j) {
                        char *prefixed_hierarchy = path_join(mount_point, hierarchies[j]);
                        if (!prefixed_hierarchy)
                                return -ENOMEM;

                        r = strv_consume(&overlays[j], TAKE_PTR(prefixed_hierarchy));
                        if (r < 0)
                                return r;
                }

                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return -ENOMEM;

                *me = (MountEntry) {
                        .path_malloc = TAKE_PTR(mount_point),
                        .source_malloc = TAKE_PTR(source),
                        .mode = MOUNT_EXTENSION_DIRECTORY,
                        .ignore = ignore_enoent,
                        .has_prefix = true,
                        .read_only = true,
                };
        }

        /* Then, for each hierarchy, prepare an overlay with the list of lowerdir= strings
         * set up earlier. */
        for (size_t i = 0; hierarchies && hierarchies[i]; ++i) {
                _cleanup_free_ char *prefixed_hierarchy = NULL;

                prefixed_hierarchy = path_join(root, hierarchies[i]);
                if (!prefixed_hierarchy)
                        return -ENOMEM;

                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return -ENOMEM;

                *me = (MountEntry) {
                        .path_malloc = TAKE_PTR(prefixed_hierarchy),
                        .overlay_layers = TAKE_PTR(overlays[i]),
                        .mode = MOUNT_OVERLAY,
                        .has_prefix = true,
                        .ignore = true, /* If the source image doesn't set the ignore bit it will fail earlier. */
                };
        }

        return 0;
}

static int append_tmpfs_mounts(MountList *ml, const TemporaryFileSystem *tmpfs, size_t n) {
        assert(ml);
        assert(tmpfs || n == 0);

        FOREACH_ARRAY(t, tmpfs, n) {
                _cleanup_free_ char *o = NULL, *str = NULL;
                unsigned long flags;
                bool ro = false;
                int r;

                if (!path_is_absolute(t->path))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Path is not absolute: %s", t->path);

                str = strjoin("mode=0755" NESTED_TMPFS_LIMITS ",", t->options);
                if (!str)
                        return -ENOMEM;

                r = mount_option_mangle(str, MS_NODEV|MS_STRICTATIME, &flags, &o);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse mount option '%s': %m", str);

                ro = flags & MS_RDONLY;
                if (ro)
                        flags ^= MS_RDONLY;

                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = t->path,
                        .mode = MOUNT_TMPFS,
                        .read_only = ro,
                        .options_malloc = TAKE_PTR(o),
                        .flags = flags,
                };
        }

        return 0;
}

static int append_static_mounts(MountList *ml, const MountEntry *mounts, size_t n, bool ignore_protect) {
        assert(ml);
        assert(mounts || n == 0);

        /* Adds a list of static pre-defined entries */

        FOREACH_ARRAY(m, mounts, n) {
                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = mount_entry_path(m),
                        .mode = m->mode,
                        .ignore = m->ignore || ignore_protect,
                };
        }

        return 0;
}

static int append_protect_home(MountList *ml, ProtectHome protect_home, bool ignore_protect) {
        assert(ml);

        switch (protect_home) {

        case PROTECT_HOME_NO:
                return 0;

        case PROTECT_HOME_READ_ONLY:
                return append_static_mounts(ml, protect_home_read_only_table, ELEMENTSOF(protect_home_read_only_table), ignore_protect);

        case PROTECT_HOME_TMPFS:
                return append_static_mounts(ml, protect_home_tmpfs_table, ELEMENTSOF(protect_home_tmpfs_table), ignore_protect);

        case PROTECT_HOME_YES:
                return append_static_mounts(ml, protect_home_yes_table, ELEMENTSOF(protect_home_yes_table), ignore_protect);

        default:
                assert_not_reached();
        }
}

static int append_protect_system(MountList *ml, ProtectSystem protect_system, bool ignore_protect) {
        assert(ml);

        switch (protect_system) {

        case PROTECT_SYSTEM_NO:
                return 0;

        case PROTECT_SYSTEM_STRICT:
                return append_static_mounts(ml, protect_system_strict_table, ELEMENTSOF(protect_system_strict_table), ignore_protect);

        case PROTECT_SYSTEM_YES:
                return append_static_mounts(ml, protect_system_yes_table, ELEMENTSOF(protect_system_yes_table), ignore_protect);

        case PROTECT_SYSTEM_FULL:
                return append_static_mounts(ml, protect_system_full_table, ELEMENTSOF(protect_system_full_table), ignore_protect);

        default:
                assert_not_reached();
        }
}

static int mount_path_compare(const MountEntry *a, const MountEntry *b) {
        int d;

        /* ExtensionImages/Directories will be used by other mounts as a base, so sort them first
         * regardless of the prefix - they are set up in the propagate directory anyway */
        d = -CMP(a->mode == MOUNT_EXTENSION_IMAGE, b->mode == MOUNT_EXTENSION_IMAGE);
        if (d != 0)
                return d;
        d = -CMP(a->mode == MOUNT_EXTENSION_DIRECTORY, b->mode == MOUNT_EXTENSION_DIRECTORY);
        if (d != 0)
                return d;

        /* If the paths are not equal, then order prefixes first */
        d = path_compare(mount_entry_path(a), mount_entry_path(b));
        if (d != 0)
                return d;

        /* If the paths are equal, check the mode */
        return CMP((int) a->mode, (int) b->mode);
}

static int prefix_where_needed(MountList *ml, const char *root_directory) {
        /* Prefixes all paths in the bind mount table with the root directory if the entry needs that. */

        assert(ml);

        FOREACH_ARRAY(me, ml->mounts, ml->n_mounts) {
                char *s;

                if (me->has_prefix)
                        continue;

                s = path_join(root_directory, mount_entry_path(me));
                if (!s)
                        return -ENOMEM;

                mount_entry_consume_prefix(me, s);
        }

        return 0;
}

static void drop_duplicates(MountList *ml) {
        MountEntry *f, *t, *previous;

        assert(ml);

        /* Drops duplicate entries. Expects that the array is properly ordered already. */

        for (f = ml->mounts, t = ml->mounts, previous = NULL; f < ml->mounts + ml->n_mounts; f++) {

                /* The first one wins (which is the one with the more restrictive mode), see mount_path_compare()
                 * above. Note that we only drop duplicates that haven't been mounted yet. */
                if (previous &&
                    path_equal(mount_entry_path(f), mount_entry_path(previous)) &&
                    f->state == MOUNT_PENDING && previous->state == MOUNT_PENDING) {
                        log_debug("%s (%s) is duplicate.", mount_entry_path(f), mount_mode_to_string(f->mode));
                        /* Propagate the flags to the remaining entry */
                        previous->read_only = previous->read_only || mount_entry_read_only(f);
                        previous->noexec = previous->noexec || mount_entry_noexec(f);
                        previous->exec = previous->exec || mount_entry_exec(f);
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                previous = t;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static void drop_inaccessible(MountList *ml) {
        MountEntry *f, *t;
        const char *clear = NULL;

        assert(ml);

        /* Drops all entries obstructed by another entry further up the tree. Expects that the array is properly
         * ordered already. */

        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {

                /* If we found a path set for INACCESSIBLE earlier, and this entry has it as prefix we should drop
                 * it, as inaccessible paths really should drop the entire subtree. */
                if (clear && path_startswith(mount_entry_path(f), clear)) {
                        log_debug("%s is masked by %s.", mount_entry_path(f), clear);
                        mount_entry_done(f);
                        continue;
                }

                clear = f->mode == MOUNT_INACCESSIBLE ? mount_entry_path(f) : NULL;

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static void drop_nop(MountList *ml) {
        MountEntry *f, *t;

        assert(ml);

        /* Drops all entries which have an immediate parent that has the same type, as they are redundant. Assumes the
         * list is ordered by prefixes. */

        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {

                /* Only suppress such subtrees for READ_ONLY, READ_WRITE and READ_WRITE_IMPLICIT entries */
                if (IN_SET(f->mode, MOUNT_READ_ONLY, MOUNT_READ_WRITE, MOUNT_READ_WRITE_IMPLICIT)) {
                        MountEntry *found = NULL;

                        /* Now let's find the first parent of the entry we are looking at. */
                        for (MountEntry *p = PTR_SUB1(t, ml->mounts); p; p = PTR_SUB1(p, ml->mounts))
                                if (path_startswith(mount_entry_path(f), mount_entry_path(p))) {
                                        found = p;
                                        break;
                                }

                        /* We found it, let's see if it's the same mode, if so, we can drop this entry */
                        if (found && found->mode == f->mode) {
                                log_debug("%s (%s) is made redundant by %s (%s)",
                                          mount_entry_path(f), mount_mode_to_string(f->mode),
                                          mount_entry_path(found), mount_mode_to_string(found->mode));
                                mount_entry_done(f);
                                continue;
                        }
                }

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static void drop_outside_root(MountList *ml, const char *root_directory) {
        MountEntry *f, *t;

        assert(ml);

        /* Nothing to do */
        if (!root_directory)
                return;

        /* Drops all mounts that are outside of the root directory. */

        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {

                /* ExtensionImages/Directories bases are opened in /run/systemd/unit-extensions on the host */
                if (!IN_SET(f->mode, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY) && !path_startswith(mount_entry_path(f), root_directory)) {
                        log_debug("%s is outside of root directory.", mount_entry_path(f));
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
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

        /* We're about to fall back to bind-mounting the device node. So create a dummy bind-mount target.
         * Do not prepare device-node SELinux label (see issue 13762) */
        r = mknod(dn, S_IFREG, 0);
        if (r < 0 && errno != EEXIST)
                return log_debug_errno(errno, "mknod() fallback failed for '%s': %m", d);

        /* Fallback to bind-mounting: The assumption here is that all used device nodes carry standard
         * properties. Specifically, the devices nodes we bind-mount should either be owned by root:root or
         * root:tty (e.g. /dev/tty, /dev/ptmx) and should not carry ACLs. */
        r = mount_nofollow_verbose(LOG_DEBUG, d, dn, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

add_symlink:
        bn = path_startswith(d, "/dev/");
        if (!bn)
                return 0;

        /* Create symlinks like /dev/char/1:9 → ../urandom */
        if (asprintf(&sl, "%s/dev/%s/" DEVNUM_FORMAT_STR,
                     temporary_mount,
                     S_ISCHR(st.st_mode) ? "char" : "block",
                     DEVNUM_FORMAT_VAL(st.st_rdev)) < 0)
                return log_oom_debug();

        (void) mkdir_parents(sl, 0755);

        t = strjoina("../", bn);
        if (symlink(t, sl) < 0)
                log_debug_errno(errno, "Failed to symlink '%s' to '%s', ignoring: %m", t, sl);

        return 0;
}

static char *settle_runtime_dir(RuntimeScope scope) {
        char *runtime_dir;

        if (scope != RUNTIME_SCOPE_USER)
                return strdup("/run/");

        if (asprintf(&runtime_dir, "/run/user/" UID_FMT, geteuid()) < 0)
                return NULL;

        return runtime_dir;
}

static int create_temporary_mount_point(RuntimeScope scope, char **ret) {
        _cleanup_free_ char *runtime_dir = NULL, *temporary_mount = NULL;

        assert(ret);

        runtime_dir = settle_runtime_dir(scope);
        if (!runtime_dir)
                return log_oom_debug();

        temporary_mount = path_join(runtime_dir, "systemd/namespace-XXXXXX");
        if (!temporary_mount)
                return log_oom_debug();

        if (!mkdtemp(temporary_mount))
                return log_debug_errno(errno, "Failed to create temporary directory '%s': %m", temporary_mount);

        *ret = TAKE_PTR(temporary_mount);
        return 0;
}

static int mount_private_dev(MountEntry *m, RuntimeScope scope) {
        static const char devnodes[] =
                "/dev/null\0"
                "/dev/zero\0"
                "/dev/full\0"
                "/dev/random\0"
                "/dev/urandom\0"
                "/dev/tty\0";

        _cleanup_free_ char *temporary_mount = NULL;
        const char *dev = NULL, *devpts = NULL, *devshm = NULL, *devhugepages = NULL, *devmqueue = NULL, *devlog = NULL, *devptmx = NULL;
        bool can_mknod = true;
        int r;

        assert(m);

        r = create_temporary_mount_point(scope, &temporary_mount);
        if (r < 0)
                return r;

        dev = strjoina(temporary_mount, "/dev");
        (void) mkdir(dev, 0755);
        r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", dev, "tmpfs", DEV_MOUNT_OPTIONS, "mode=0755" TMPFS_LIMITS_PRIVATE_DEV);
        if (r < 0)
                goto fail;

        r = label_fix_full(AT_FDCWD, dev, "/dev", 0);
        if (r < 0) {
                log_debug_errno(r, "Failed to fix label of '%s' as /dev: %m", dev);
                goto fail;
        }

        devpts = strjoina(temporary_mount, "/dev/pts");
        (void) mkdir(devpts, 0755);
        r = mount_nofollow_verbose(LOG_DEBUG, "/dev/pts", devpts, NULL, MS_BIND, NULL);
        if (r < 0)
                goto fail;

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
        r = mount_nofollow_verbose(LOG_DEBUG, "/dev/shm", devshm, NULL, MS_BIND, NULL);
        if (r < 0)
                goto fail;

        devmqueue = strjoina(temporary_mount, "/dev/mqueue");
        (void) mkdir(devmqueue, 0755);
        (void) mount_nofollow_verbose(LOG_DEBUG, "/dev/mqueue", devmqueue, NULL, MS_BIND, NULL);

        devhugepages = strjoina(temporary_mount, "/dev/hugepages");
        (void) mkdir(devhugepages, 0755);
        (void) mount_nofollow_verbose(LOG_DEBUG, "/dev/hugepages", devhugepages, NULL, MS_BIND, NULL);

        devlog = strjoina(temporary_mount, "/dev/log");
        if (symlink("/run/systemd/journal/dev-log", devlog) < 0)
                log_debug_errno(errno, "Failed to create a symlink '%s' to /run/systemd/journal/dev-log, ignoring: %m", devlog);

        NULSTR_FOREACH(d, devnodes) {
                r = clone_device_node(d, temporary_mount, &can_mknod);
                /* ENXIO means the *source* is not a device file, skip creation in that case */
                if (r < 0 && r != -ENXIO)
                        goto fail;
        }

        r = dev_setup(temporary_mount, UID_INVALID, GID_INVALID);
        if (r < 0)
                log_debug_errno(r, "Failed to set up basic device tree at '%s', ignoring: %m", temporary_mount);

        /* Create the /dev directory if missing. It is more likely to be missing when the service is started
         * with RootDirectory. This is consistent with mount units creating the mount points when missing. */
        (void) mkdir_p_label(mount_entry_path(m), 0755);

        /* Unmount everything in old /dev */
        r = umount_recursive(mount_entry_path(m), 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below '%s', ignoring: %m", mount_entry_path(m));

        r = mount_nofollow_verbose(LOG_DEBUG, dev, mount_entry_path(m), NULL, MS_MOVE, NULL);
        if (r < 0)
                goto fail;

        (void) rmdir(dev);
        (void) rmdir(temporary_mount);

        return 1;

fail:
        if (devpts)
                (void) umount_verbose(LOG_DEBUG, devpts, UMOUNT_NOFOLLOW);

        if (devshm)
                (void) umount_verbose(LOG_DEBUG, devshm, UMOUNT_NOFOLLOW);

        if (devhugepages)
                (void) umount_verbose(LOG_DEBUG, devhugepages, UMOUNT_NOFOLLOW);

        if (devmqueue)
                (void) umount_verbose(LOG_DEBUG, devmqueue, UMOUNT_NOFOLLOW);

        (void) umount_verbose(LOG_DEBUG, dev, UMOUNT_NOFOLLOW);
        (void) rmdir(dev);
        (void) rmdir(temporary_mount);

        return r;
}

static int mount_bind_dev(const MountEntry *m) {
        int r;

        assert(m);

        /* Implements the little brother of mount_private_dev(): simply bind mounts the host's /dev into the
         * service's /dev. This is only used when RootDirectory= is set. */

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m), NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /dev is already mounted: %m");
        if (r > 0) /* make this a NOP if /dev is already a mount point */
                return 0;

        r = mount_nofollow_verbose(LOG_DEBUG, "/dev", mount_entry_path(m), NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int mount_bind_sysfs(const MountEntry *m) {
        int r;

        assert(m);

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m), NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /sys is already mounted: %m");
        if (r > 0) /* make this a NOP if /sys is already a mount point */
                return 0;

        /* Bind mount the host's version so that we get all child mounts of it, too. */
        r = mount_nofollow_verbose(LOG_DEBUG, "/sys", mount_entry_path(m), NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int mount_private_apivfs(
                const char *fstype,
                const char *entry_path,
                const char *bind_source,
                const char *opts,
                RuntimeScope scope) {

        _cleanup_(rmdir_and_freep) char *temporary_mount = NULL;
        int r;

        assert(fstype);
        assert(entry_path);
        assert(bind_source);

        (void) mkdir_p_label(entry_path, 0755);

        /* First, check if we have enough privileges to mount a new instance. Note, a new sysfs instance
         * cannot be mounted on an already existing mount. Let's use a temporary place. */
        r = create_temporary_mount_point(scope, &temporary_mount);
        if (r < 0)
                return r;

        r = mount_nofollow_verbose(LOG_DEBUG, fstype, temporary_mount, fstype, MS_NOSUID|MS_NOEXEC|MS_NODEV, opts);
        if (r == -EINVAL && opts)
                /* If this failed with EINVAL then this likely means the textual hidepid= stuff for procfs is
                 * not supported by the kernel, and thus the per-instance hidepid= neither, which means we
                 * really don't want to use it, since it would affect our host's /proc mount. Hence let's
                 * gracefully fallback to a classic, unrestricted version. */
                r = mount_nofollow_verbose(LOG_DEBUG, fstype, temporary_mount, fstype, MS_NOSUID|MS_NOEXEC|MS_NODEV, /* opts = */ NULL);
        if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                /* When we do not have enough privileges to mount a new instance, fall back to use an
                 * existing mount. */

                r = path_is_mount_point(entry_path, /* root = */ NULL, /* flags = */ 0);
                if (r < 0)
                        return log_debug_errno(r, "Unable to determine whether '%s' is already mounted: %m", entry_path);
                if (r > 0)
                        return 0; /* Use the current mount as is. */

                /* We lack permissions to mount a new instance, and it is not already mounted. But we can
                 * access the host's, so as a final fallback bind-mount it to the destination, as most likely
                 * we are inside a user manager in an unprivileged user namespace. */
                r = mount_nofollow_verbose(LOG_DEBUG, bind_source, entry_path, /* fstype = */ NULL, MS_BIND|MS_REC, /* opts = */ NULL);
                if (r < 0)
                        return r;

                return 1;

        } else if (r < 0)
                return r;

        /* OK. We have a new mount instance. Let's clear an existing mount and its submounts. */
        r = umount_recursive(entry_path, /* flags = */ 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below '%s', ignoring: %m", entry_path);

        /* Then, move the new mount instance. */
        r = mount_nofollow_verbose(LOG_DEBUG, temporary_mount, entry_path, /* fstype = */ NULL, MS_MOVE, /* opts = */ NULL);
        if (r < 0)
                return r;

        /* We mounted a new instance now. Let's bind mount the children over now. This matters for nspawn
         * where a bunch of files are overmounted, in particular the boot id. */
        (void) bind_mount_submounts(bind_source, entry_path);
        return 1;
}

static int mount_private_sysfs(const MountEntry *m, const NamespaceParameters *p) {
        assert(m);
        assert(p);
        return mount_private_apivfs("sysfs", mount_entry_path(m), "/sys", /* opts = */ NULL, p->runtime_scope);
}

static int mount_procfs(const MountEntry *m, const NamespaceParameters *p) {
        _cleanup_free_ char *opts = NULL;

        assert(m);
        assert(p);

        if (p->protect_proc != PROTECT_PROC_DEFAULT ||
            p->proc_subset != PROC_SUBSET_ALL) {

                /* Starting with kernel 5.8 procfs' hidepid= logic is truly per-instance (previously it
                 * pretended to be per-instance but actually was per-namespace), hence let's make use of it
                 * if requested. To make sure this logic succeeds only on kernels where hidepid= is
                 * per-instance, we'll exclusively use the textual value for hidepid=, since support was
                 * added in the same commit: if it's supported it is thus also per-instance. */

                const char *hpv = p->protect_proc == PROTECT_PROC_DEFAULT ?
                                  "off" :
                                  protect_proc_to_string(p->protect_proc);

                /* hidepid= support was added in 5.8, so we can use fsconfig()/fsopen() (which were added in
                 * 5.2) to check if hidepid= is supported. This avoids a noisy dmesg log by the kernel when
                 * trying to use hidepid= on systems where it isn't supported. The same applies for subset=.
                 * fsopen()/fsconfig() was also backported on some distros which allows us to detect
                 * hidepid=/subset= support in even more scenarios. */

                if (mount_option_supported("proc", "hidepid", hpv) != 0) {
                        opts = strjoin("hidepid=", hpv);
                        if (!opts)
                                return -ENOMEM;
                }

                if (p->proc_subset == PROC_SUBSET_PID &&
                    mount_option_supported("proc", "subset", "pid") != 0)
                        if (!strextend_with_separator(&opts, ",", "subset=pid"))
                                return -ENOMEM;
        }

        /* Mount a new instance, so that we get the one that matches our user namespace, if we are running in
         * one. i.e we don't reuse existing mounts here under any condition, we want a new instance owned by
         * our user namespace and with our hidepid= settings applied. Hence, let's get rid of everything
         * mounted on /proc/ first. */
        return mount_private_apivfs("proc", mount_entry_path(m), "/proc", opts, p->runtime_scope);
}

static int mount_tmpfs(const MountEntry *m) {
        const char *entry_path, *inner_path;
        int r;

        assert(m);

        entry_path = mount_entry_path(m);
        inner_path = mount_entry_unprefixed_path(m);

        /* First, get rid of everything that is below if there is anything. Then, overmount with our new
         * tmpfs */

        (void) mkdir_p_label(entry_path, 0755);
        (void) umount_recursive(entry_path, 0);

        r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", entry_path, "tmpfs", m->flags, mount_entry_options(m));
        if (r < 0)
                return r;

        r = label_fix_full(AT_FDCWD, entry_path, inner_path, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to fix label of '%s' as '%s': %m", entry_path, inner_path);

        return 1;
}

static int mount_run(const MountEntry *m) {
        int r;

        assert(m);

        r = path_is_mount_point(mount_entry_path(m), NULL, 0);
        if (r < 0 && r != -ENOENT)
                return log_debug_errno(r, "Unable to determine whether /run is already mounted: %m");
        if (r > 0) /* make this a NOP if /run is already a mount point */
                return 0;

        return mount_tmpfs(m);
}

static int mount_mqueuefs(const MountEntry *m) {
        int r;
        const char *entry_path;

        assert(m);

        entry_path = mount_entry_path(m);

        (void) mkdir_p_label(entry_path, 0755);
        (void) umount_recursive(entry_path, 0);

        r = mount_nofollow_verbose(LOG_DEBUG, "mqueue", entry_path, "mqueue", m->flags, mount_entry_options(m));
        if (r < 0)
                return r;

        return 1;
}

static int mount_image(
                const MountEntry *m,
                const char *root_directory,
                const ImagePolicy *image_policy) {

        _cleanup_free_ char *host_os_release_id = NULL, *host_os_release_version_id = NULL,
                            *host_os_release_sysext_level = NULL, *host_os_release_confext_level = NULL,
                            *extension_name = NULL;
        int r;

        assert(m);

        r = path_extract_filename(mount_entry_source(m), &extension_name);
        if (r < 0)
                return log_debug_errno(r, "Failed to extract extension name from %s: %m", mount_entry_source(m));

        if (m->mode == MOUNT_EXTENSION_IMAGE) {
                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &host_os_release_id,
                                "VERSION_ID", &host_os_release_version_id,
                                image_class_info[IMAGE_SYSEXT].level_env, &host_os_release_sysext_level,
                                image_class_info[IMAGE_CONFEXT].level_env, &host_os_release_confext_level,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
                if (isempty(host_os_release_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'ID' field not found or empty in 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
        }

        r = verity_dissect_and_mount(
                        /* src_fd= */ -1,
                        mount_entry_source(m),
                        mount_entry_path(m),
                        m->image_options_const,
                        image_policy,
                        host_os_release_id,
                        host_os_release_version_id,
                        host_os_release_sysext_level,
                        host_os_release_confext_level,
                        /* required_sysext_scope= */ NULL,
                        /* ret_image= */ NULL);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r == -ESTALE && host_os_release_id)
                return log_error_errno(r, // FIXME: this should not be logged ad LOG_ERR, as it will result in duplicate logging.
                                       "Failed to mount image %s, extension-release metadata does not match the lower layer's: ID=%s%s%s%s%s%s%s",
                                       mount_entry_source(m),
                                       host_os_release_id,
                                       host_os_release_version_id ? " VERSION_ID=" : "",
                                       strempty(host_os_release_version_id),
                                       host_os_release_sysext_level ? image_class_info[IMAGE_SYSEXT].level_env_print : "",
                                       strempty(host_os_release_sysext_level),
                                       host_os_release_confext_level ? image_class_info[IMAGE_CONFEXT].level_env_print : "",
                                       strempty(host_os_release_confext_level));
        if (r < 0)
                return log_debug_errno(r, "Failed to mount image %s on %s: %m", mount_entry_source(m), mount_entry_path(m));

        return 1;
}

static int mount_overlay(const MountEntry *m) {
        _cleanup_free_ char *options = NULL, *layers = NULL;
        int r;

        assert(m);

        /* Extension hierarchies are optional (e.g.: confext might not have /opt) so check if they actually
         * exist in an image before attempting to create an overlay with them, otherwise the mount will
         * fail. We can't check before this, as the images will not be mounted until now. */

        /* Note that lowerdir= parameters are in 'reverse' order, so the top-most directory in the overlay
         * comes first in the list. */
        STRV_FOREACH_BACKWARDS(o, m->overlay_layers) {
                _cleanup_free_ char *escaped = NULL;

                r = is_dir(*o, /* follow= */ false);
                if (r <= 0) {
                        if (r != -ENOENT)
                                log_debug_errno(r,
                                                "Failed to check whether overlay layer source path '%s' exists, ignoring: %m",
                                                *o);
                        continue;
                }

                escaped = shell_escape(*o, ",:");
                if (!escaped)
                        return log_oom_debug();

                if (!strextend_with_separator(&layers, ":", escaped))
                        return log_oom_debug();
        }

        if (!layers) {
                log_debug("None of the overlays specified in '%s' exist at the source, skipping.",
                          mount_entry_options(m));
                return 0; /* Only the root is set? Then there's nothing to overlay */
        }

        options = strjoin("lowerdir=", layers, ":", mount_entry_path(m)); /* The root goes in last */
        if (!options)
                return log_oom_debug();

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = mount_nofollow_verbose(LOG_DEBUG, "overlay", mount_entry_path(m), "overlay", MS_RDONLY, options);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return r;

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

        r = chase(mount_entry_path(m), root_directory, CHASE_STEP|CHASE_NONEXISTENT, &target, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to chase symlinks '%s': %m", mount_entry_path(m));
        if (r > 0) /* Reached the end, nothing more to resolve */
                return 1;

        if (m->n_followed >= CHASE_MAX) /* put a boundary on things */
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Symlink loop on '%s'.",
                                       mount_entry_path(m));

        log_debug("Followed mount entry path symlink %s %s %s.",
                  mount_entry_path(m), special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), target);

        mount_entry_consume_prefix(m, TAKE_PTR(target));

        m->n_followed++;

        return 0;
}

static int apply_one_mount(
                const char *root_directory,
                MountEntry *m,
                const NamespaceParameters *p) {

        _cleanup_free_ char *inaccessible = NULL;
        bool rbind = true, make = false;
        const char *what;
        int r;

        /* Return 1 when the mount should be post-processed (remounted r/o, etc.), 0 otherwise. In most
         * cases post-processing is the right thing, the typical exception is when the mount is gracefully
         * skipped. */

        assert(m);
        assert(p);

        log_debug("Applying namespace mount on %s", mount_entry_path(m));

        switch (m->mode) {

        case MOUNT_INACCESSIBLE: {
                _cleanup_free_ char *runtime_dir = NULL;
                struct stat target;

                /* First, get rid of everything that is below if there
                 * is anything... Then, overmount it with an
                 * inaccessible path. */
                (void) umount_recursive(mount_entry_path(m), 0);

                if (lstat(mount_entry_path(m), &target) < 0) {
                        if (errno == ENOENT && m->ignore)
                                return 0;

                        return log_debug_errno(errno, "Failed to lstat() %s to determine what to mount over it: %m",
                                               mount_entry_path(m));
                }

                /* We don't pass the literal runtime scope through here but one based purely on our UID. This
                 * means that the root user's --user services will use the host's inaccessible inodes rather
                 * then root's private ones. This is preferable since it means device nodes that are
                 * overmounted to make them inaccessible will be overmounted with a device node, rather than
                 * an AF_UNIX socket inode. */
                runtime_dir = settle_runtime_dir(geteuid() == 0 ? RUNTIME_SCOPE_SYSTEM : RUNTIME_SCOPE_USER);
                if (!runtime_dir)
                        return log_oom_debug();

                r = mode_to_inaccessible_node(runtime_dir, target.st_mode, &inaccessible);
                if (r < 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                               "File type not supported for inaccessible mounts. Note that symlinks are not allowed");
                what = inaccessible;
                break;
        }

        case MOUNT_READ_ONLY:
        case MOUNT_READ_WRITE:
        case MOUNT_READ_WRITE_IMPLICIT:
        case MOUNT_EXEC:
        case MOUNT_NOEXEC:
                r = path_is_mount_point(mount_entry_path(m), root_directory, 0);
                if (r == -ENOENT && m->ignore)
                        return 0;
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine whether %s is already a mount point: %m",
                                               mount_entry_path(m));
                if (r > 0) /* Nothing to do here, it is already a mount. We just later toggle the MS_RDONLY
                            * and MS_NOEXEC bits for the mount point if needed. */
                        return 1;
                /* This isn't a mount point yet, let's make it one. */
                what = mount_entry_path(m);
                break;

        case MOUNT_EXTENSION_DIRECTORY: {
                _cleanup_free_ char *host_os_release_id = NULL, *host_os_release_version_id = NULL,
                                *host_os_release_level = NULL, *extension_name = NULL;
                _cleanup_strv_free_ char **extension_release = NULL;
                ImageClass class = IMAGE_SYSEXT;

                r = path_extract_filename(mount_entry_source(m), &extension_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extract extension name from %s: %m", mount_entry_source(m));

                r = load_extension_release_pairs(mount_entry_source(m), IMAGE_SYSEXT, extension_name, /* relax_extension_release_check= */ false, &extension_release);
                if (r == -ENOENT) {
                        r = load_extension_release_pairs(mount_entry_source(m), IMAGE_CONFEXT, extension_name, /* relax_extension_release_check= */ false, &extension_release);
                        if (r >= 0)
                                class = IMAGE_CONFEXT;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'extension-release' data of extension tree %s: %m", mount_entry_source(m));

                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &host_os_release_id,
                                "VERSION_ID", &host_os_release_version_id,
                                image_class_info[class].level_env, &host_os_release_level,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
                if (isempty(host_os_release_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'ID' field not found or empty in 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));

                r = load_extension_release_pairs(mount_entry_source(m), class, extension_name, /* relax_extension_release_check= */ false, &extension_release);
                if (r == -ENOENT && m->ignore)
                        return 0;
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse directory %s extension-release metadata: %m", extension_name);

                r = extension_release_validate(
                                extension_name,
                                host_os_release_id,
                                host_os_release_version_id,
                                host_os_release_level,
                                /* host_extension_scope */ NULL, /* Leave empty, we need to accept both system and portable */
                                extension_release,
                                class);
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Directory %s extension-release metadata does not match the root's", extension_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to compare directory %s extension-release metadata with the root's os-release: %m", extension_name);

                _fallthrough_;
        }

        case MOUNT_BIND:
                rbind = false;

                _fallthrough_;
        case MOUNT_BIND_RECURSIVE: {
                _cleanup_free_ char *chased = NULL;

                /* Since mount() will always follow symlinks we chase the symlinks on our own first. Note
                 * that bind mount source paths are always relative to the host root, hence we pass NULL as
                 * root directory to chase() here. */

                r = chase(mount_entry_source(m), NULL, CHASE_TRAIL_SLASH, &chased, NULL);
                if (r == -ENOENT && m->ignore) {
                        log_debug_errno(r, "Path %s does not exist, ignoring.", mount_entry_source(m));
                        return 0;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to follow symlinks on %s: %m", mount_entry_source(m));

                log_debug("Followed source symlinks %s %s %s.",
                          mount_entry_source(m), special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), chased);

                free_and_replace(m->source_malloc, chased);

                what = mount_entry_source(m);
                make = true;
                break;
        }

        case MOUNT_EMPTY_DIR:
        case MOUNT_TMPFS:
                return mount_tmpfs(m);

        case MOUNT_PRIVATE_TMP:
        case MOUNT_PRIVATE_TMP_READ_ONLY:
                what = mount_entry_source(m);
                make = true;
                break;

        case MOUNT_PRIVATE_DEV:
                return mount_private_dev(m, p->runtime_scope);

        case MOUNT_BIND_DEV:
                return mount_bind_dev(m);

        case MOUNT_PRIVATE_SYSFS:
                return mount_private_sysfs(m, p);

        case MOUNT_BIND_SYSFS:
                return mount_bind_sysfs(m);

        case MOUNT_PROCFS:
                return mount_procfs(m, p);

        case MOUNT_RUN:
                return mount_run(m);

        case MOUNT_MQUEUEFS:
                return mount_mqueuefs(m);

        case MOUNT_IMAGE:
                return mount_image(m, NULL, p->mount_image_policy);

        case MOUNT_EXTENSION_IMAGE:
                return mount_image(m, root_directory, p->extension_image_policy);

        case MOUNT_OVERLAY:
                return mount_overlay(m);

        default:
                assert_not_reached();
        }

        assert(what);

        r = mount_nofollow_verbose(LOG_DEBUG, what, mount_entry_path(m), NULL, MS_BIND|(rbind ? MS_REC : 0), NULL);
        if (r < 0) {
                bool try_again = false;

                if (r == -ENOENT && make) {
                        int q;

                        /* Hmm, either the source or the destination are missing. Let's see if we can create
                           the destination, then try again. */

                        (void) mkdir_parents(mount_entry_path(m), 0755);

                        q = make_mount_point_inode_from_path(what, mount_entry_path(m), 0755);
                        if (q < 0) {
                                if (q != -EEXIST) // FIXME: this shouldn't be logged at LOG_WARNING, but be bubbled up, and logged there to avoid duplicate logging
                                        log_warning_errno(q, "Failed to create destination mount point node '%s', ignoring: %m",
                                                          mount_entry_path(m));
                        } else
                                try_again = true;
                }

                if (try_again)
                        r = mount_nofollow_verbose(LOG_DEBUG, what, mount_entry_path(m), NULL, MS_BIND|(rbind ? MS_REC : 0), NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount %s to %s: %m", what, mount_entry_path(m)); // FIXME: this should not be logged here, but be bubbled up, to avoid duplicate logging
        }

        log_debug("Successfully mounted %s to %s", what, mount_entry_path(m));
        return 1;
}

static int make_read_only(const MountEntry *m, char **deny_list, FILE *proc_self_mountinfo) {
        unsigned long new_flags = 0, flags_mask = 0;
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        if (mount_entry_read_only(m) || m->mode == MOUNT_PRIVATE_DEV) {
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
                !IN_SET(m->mode, MOUNT_EMPTY_DIR, MOUNT_TMPFS);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, deny_list, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, proc_self_mountinfo);

        /* Note that we only turn on the MS_RDONLY flag here, we never turn it off. Something that was marked
         * read-only already stays this way. This improves compatibility with container managers, where we
         * won't attempt to undo read-only mounts already applied. */

        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

static int make_noexec(const MountEntry *m, char **deny_list, FILE *proc_self_mountinfo) {
        unsigned long new_flags = 0, flags_mask = 0;
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        if (mount_entry_noexec(m)) {
                new_flags |= MS_NOEXEC;
                flags_mask |= MS_NOEXEC;
        } else if (mount_entry_exec(m)) {
                new_flags &= ~MS_NOEXEC;
                flags_mask |= MS_NOEXEC;
        }

        if (flags_mask == 0) /* No Change? */
                return 0;

        submounts = !IN_SET(m->mode, MOUNT_EMPTY_DIR, MOUNT_TMPFS);

        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, deny_list, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(mount_entry_path(m), new_flags, flags_mask, proc_self_mountinfo);

        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

static int make_nosuid(const MountEntry *m, FILE *proc_self_mountinfo) {
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        submounts = !IN_SET(m->mode, MOUNT_EMPTY_DIR, MOUNT_TMPFS);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(mount_entry_path(m), MS_NOSUID, MS_NOSUID, NULL, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(mount_entry_path(m), MS_NOSUID, MS_NOSUID, proc_self_mountinfo);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", mount_entry_path(m),
                                       submounts ? " and its submounts" : "");
        return 0;
}

static bool namespace_parameters_mount_apivfs(const NamespaceParameters *p) {
        assert(p);

        /*
         * ProtectControlGroups= and ProtectKernelTunables= imply MountAPIVFS=,
         * since to protect the API VFS mounts, they need to be around in the
         * first place...
         */

        return p->mount_apivfs ||
                p->protect_control_groups ||
                p->protect_kernel_tunables ||
                p->protect_proc != PROTECT_PROC_DEFAULT ||
                p->proc_subset != PROC_SUBSET_ALL;
}

/* Walk all mount entries and dropping any unused mounts. This affects all
 * mounts:
 * - that are implicitly protected by a path that has been rendered inaccessible
 * - whose immediate parent requests the same protection mode as the mount itself
 * - that are outside of the relevant root directory
 * - which are duplicates
 */
static void drop_unused_mounts(MountList *ml, const char *root_directory) {
        assert(ml);
        assert(root_directory);

        assert(ml->mounts || ml->n_mounts == 0);

        typesafe_qsort(ml->mounts, ml->n_mounts, mount_path_compare);

        drop_duplicates(ml);
        drop_outside_root(ml, root_directory);
        drop_inaccessible(ml);
        drop_nop(ml);
}

static int create_symlinks_from_tuples(const char *root, char **strv_symlinks) {
        int r;

        STRV_FOREACH_PAIR(src, dst, strv_symlinks) {
                _cleanup_free_ char *src_abs = NULL, *dst_abs = NULL;

                src_abs = path_join(root, *src);
                dst_abs = path_join(root, *dst);
                if (!src_abs || !dst_abs)
                        return -ENOMEM;

                r = mkdir_parents_label(dst_abs, 0755);
                if (r < 0)
                        return log_debug_errno(
                                        r,
                                        "Failed to create parent directory for symlink '%s': %m",
                                        dst_abs);

                r = symlink_idempotent(src_abs, dst_abs, true);
                if (r < 0)
                        return log_debug_errno(
                                        r,
                                        "Failed to create symlink from '%s' to '%s': %m",
                                        src_abs,
                                        dst_abs);
        }

        return 0;
}

static void mount_entry_path_debug_string(const char *root, MountEntry *m, char **error_path) {
        assert(m);

        /* Create a string suitable for debugging logs, stripping for example the local working directory.
         * For example, with a BindPaths=/var/bar that does not exist on the host:
         *
         * Before:
         *  foo.service: Failed to set up mount namespacing: /run/systemd/unit-root/var/bar: No such file or directory
         * After:
         *  foo.service: Failed to set up mount namespacing: /var/bar: No such file or directory
         *
         * Note that this is an error path, so no OOM check is done on purpose. */

        if (!error_path)
                return;

        if (!mount_entry_path(m)) {
                *error_path = NULL;
                return;
        }

        if (root) {
                const char *e = startswith(mount_entry_path(m), root);
                if (e) {
                        *error_path = strdup(e);
                        return;
                }
        }

        *error_path = strdup(mount_entry_path(m));
        return;
}

static int apply_mounts(
                MountList *ml,
                const char *root,
                const NamespaceParameters *p,
                char **error_path) {

        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        _cleanup_free_ char **deny_list = NULL;
        int r;

        assert(ml);
        assert(root);
        assert(p);

        if (ml->n_mounts == 0) /* Shortcut: nothing to do */
                return 0;

        /* Open /proc/self/mountinfo now as it may become unavailable if we mount anything on top of
         * /proc. For example, this is the case with the option: 'InaccessiblePaths=/proc'. */
        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo) {
                r = -errno;

                if (error_path)
                        *error_path = strdup("/proc/self/mountinfo");

                return log_debug_errno(r, "Failed to open /proc/self/mountinfo: %m");
        }

        /* First round, establish all mounts we need */
        for (;;) {
                bool again = false;

                FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {

                        if (m->state != MOUNT_PENDING)
                                continue;

                        /* ExtensionImages/Directories are first opened in the propagate directory, not in the root_directory */
                        r = follow_symlink(!IN_SET(m->mode, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY) ? root : NULL, m);
                        if (r < 0) {
                                mount_entry_path_debug_string(root, m, error_path);
                                return r;
                        }
                        if (r == 0) {
                                /* We hit a symlinked mount point. The entry got rewritten and might
                                 * point to a very different place now. Let's normalize the changed
                                 * list, and start from the beginning. After all to mount the entry
                                 * at the new location we might need some other mounts first */
                                again = true;
                                break;
                        }

                        /* Returns 1 if the mount should be post-processed, 0 otherwise */
                        r = apply_one_mount(root, m, p);
                        if (r < 0) {
                                mount_entry_path_debug_string(root, m, error_path);
                                return r;
                        }
                        m->state = r == 0 ? MOUNT_SKIPPED : MOUNT_APPLIED;
                }

                if (!again)
                        break;

                drop_unused_mounts(ml, root);
        }

        /* Now that all filesystems have been set up, but before the
         * read-only switches are flipped, create the exec dirs and other symlinks.
         * Note that when /var/lib is not empty/tmpfs, these symlinks will already
         * exist, which means this will be a no-op. */
        r = create_symlinks_from_tuples(root, p->symlinks);
        if (r < 0)
                return log_debug_errno(r, "Failed to set up symlinks inside mount namespace: %m");

        /* Create a deny list we can pass to bind_mount_recursive() */
        deny_list = new(char*, ml->n_mounts+1);
        if (!deny_list)
                return -ENOMEM;
        for (size_t j = 0; j < ml->n_mounts; j++)
                deny_list[j] = (char*) mount_entry_path(ml->mounts+j);
        deny_list[ml->n_mounts] = NULL;

        /* Second round, flip the ro bits if necessary. */
        FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {
                r = make_read_only(m, deny_list, proc_self_mountinfo);
                if (r < 0) {
                        mount_entry_path_debug_string(root, m, error_path);
                        return r;
                }
        }

        /* Third round, flip the noexec bits with a simplified deny list. */
        for (size_t j = 0; j < ml->n_mounts; j++)
                if (IN_SET((ml->mounts+j)->mode, MOUNT_EXEC, MOUNT_NOEXEC))
                        deny_list[j] = (char*) mount_entry_path(ml->mounts+j);
        deny_list[ml->n_mounts] = NULL;

        FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {
                r = make_noexec(m, deny_list, proc_self_mountinfo);
                if (r < 0) {
                        mount_entry_path_debug_string(root, m, error_path);
                        return r;
                }
        }

        /* Fourth round, flip the nosuid bits without a deny list. */
        if (p->mount_nosuid)
                FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {
                        r = make_nosuid(m, proc_self_mountinfo);
                        if (r < 0) {
                                mount_entry_path_debug_string(root, m, error_path);
                                return r;
                        }
                }

        return 1;
}

static bool root_read_only(
                char **read_only_paths,
                ProtectSystem protect_system) {

        /* Determine whether the root directory is going to be read-only given the configured settings. */

        if (protect_system == PROTECT_SYSTEM_STRICT)
                return true;

        if (prefixed_path_strv_contains(read_only_paths, "/"))
                return true;

        return false;
}

static bool home_read_only(
                char** read_only_paths,
                char** inaccessible_paths,
                char** empty_directories,
                const BindMount *bind_mounts,
                size_t n_bind_mounts,
                const TemporaryFileSystem *temporary_filesystems,
                size_t n_temporary_filesystems,
                ProtectHome protect_home) {

        /* Determine whether the /home directory is going to be read-only given the configured settings. Yes,
         * this is a bit sloppy, since we don't bother checking for cases where / is affected by multiple
         * settings. */

        if (protect_home != PROTECT_HOME_NO)
                return true;

        if (prefixed_path_strv_contains(read_only_paths, "/home") ||
            prefixed_path_strv_contains(inaccessible_paths, "/home") ||
            prefixed_path_strv_contains(empty_directories, "/home"))
                return true;

        for (size_t i = 0; i < n_temporary_filesystems; i++)
                if (path_equal(temporary_filesystems[i].path, "/home"))
                        return true;

        /* If /home is overmounted with some dir from the host it's not writable. */
        for (size_t i = 0; i < n_bind_mounts; i++)
                if (path_equal(bind_mounts[i].destination, "/home"))
                        return true;

        return false;
}

int setup_namespace(const NamespaceParameters *p, char **error_path) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_strv_free_ char **hierarchies = NULL;
        _cleanup_(mount_list_done) MountList ml = {};
        bool require_prefix = false;
        const char *root;
        DissectImageFlags dissect_image_flags =
                DISSECT_IMAGE_GENERIC_ROOT |
                DISSECT_IMAGE_REQUIRE_ROOT |
                DISSECT_IMAGE_DISCARD_ON_LOOP |
                DISSECT_IMAGE_RELAX_VAR_CHECK |
                DISSECT_IMAGE_FSCK |
                DISSECT_IMAGE_USR_NO_ROOT |
                DISSECT_IMAGE_GROWFS |
                DISSECT_IMAGE_ADD_PARTITION_DEVICES |
                DISSECT_IMAGE_PIN_PARTITION_DEVICES;
        int r;

        assert(p);

        /* Make sure that all mknod(), mkdir() calls we do are unaffected by the umask, and the access modes
         * we configure take effect */
        BLOCK_WITH_UMASK(0000);

        bool setup_propagate = !isempty(p->propagate_dir) && !isempty(p->incoming_dir);
        unsigned long mount_propagation_flag = p->mount_propagation_flag != 0 ? p->mount_propagation_flag : MS_SHARED;

        if (p->root_image) {
                /* Make the whole image read-only if we can determine that we only access it in a read-only fashion. */
                if (root_read_only(p->read_only_paths,
                                   p->protect_system) &&
                    home_read_only(p->read_only_paths, p->inaccessible_paths, p->empty_directories,
                                   p->bind_mounts, p->n_bind_mounts, p->temporary_filesystems, p->n_temporary_filesystems,
                                   p->protect_home) &&
                    strv_isempty(p->read_write_paths))
                        dissect_image_flags |= DISSECT_IMAGE_READ_ONLY;

                SET_FLAG(dissect_image_flags, DISSECT_IMAGE_NO_PARTITION_TABLE, p->verity && p->verity->data_path);

                r = loop_device_make_by_path(
                                p->root_image,
                                FLAGS_SET(dissect_image_flags, DISSECT_IMAGE_DEVICE_READ_ONLY) ? O_RDONLY : -1 /* < 0 means writable if possible, read-only as fallback */,
                                /* sector_size= */ UINT32_MAX,
                                FLAGS_SET(dissect_image_flags, DISSECT_IMAGE_NO_PARTITION_TABLE) ? 0 : LO_FLAGS_PARTSCAN,
                                LOCK_SH,
                                &loop_device);
                if (r < 0)
                        return log_debug_errno(r, "Failed to create loop device for root image: %m");

                r = dissect_loop_device(
                                loop_device,
                                p->verity,
                                p->root_image_options,
                                p->root_image_policy,
                                dissect_image_flags,
                                &dissected_image);
                if (r < 0)
                        return log_debug_errno(r, "Failed to dissect image: %m");

                r = dissected_image_load_verity_sig_partition(
                                dissected_image,
                                loop_device->fd,
                                p->verity);
                if (r < 0)
                        return r;

                r = dissected_image_decrypt(
                                dissected_image,
                                NULL,
                                p->verity,
                                dissect_image_flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to decrypt dissected image: %m");
        }

        if (p->root_directory)
                root = p->root_directory;
        else {
                /* /run/systemd should have been created by PID 1 early on already, but in some cases, like
                 * when running tests (test-execute), it might not have been created yet so let's make sure
                 * we create it if it doesn't already exist. */
                (void) mkdir_p_label("/run/systemd", 0755);

                /* Always create the mount namespace in a temporary directory, instead of operating directly
                 * in the root. The temporary directory prevents any mounts from being potentially obscured
                 * my other mounts we already applied.  We use the same mount point for all images, which is
                 * safe, since they all live in their own namespaces after all, and hence won't see each
                 * other. (Note: this directory is also created by PID 1 early on, we create it here for
                 * similar reasons as /run/systemd/ first.) */
                root = "/run/systemd/mount-rootfs";
                (void) mkdir_label(root, 0555);

                require_prefix = true;
        }

        if (p->n_extension_images > 0 || !strv_isempty(p->extension_directories)) {
                /* Hierarchy population needs to be done for sysext and confext extension images */
                r = parse_env_extension_hierarchies(&hierarchies, "SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES");
                if (r < 0)
                        return r;
        }

        r = append_access_mounts(&ml, p->read_write_paths, MOUNT_READ_WRITE, require_prefix);
        if (r < 0)
                return r;

        r = append_access_mounts(&ml, p->read_only_paths, MOUNT_READ_ONLY, require_prefix);
        if (r < 0)
                return r;

        r = append_access_mounts(&ml, p->inaccessible_paths, MOUNT_INACCESSIBLE, require_prefix);
        if (r < 0)
                return r;

        r = append_access_mounts(&ml, p->exec_paths, MOUNT_EXEC, require_prefix);
        if (r < 0)
                return r;

        r = append_access_mounts(&ml, p->no_exec_paths, MOUNT_NOEXEC, require_prefix);
        if (r < 0)
                return r;

        r = append_empty_dir_mounts(&ml, p->empty_directories);
        if (r < 0)
                return r;

        r = append_bind_mounts(&ml, p->bind_mounts, p->n_bind_mounts);
        if (r < 0)
                return r;

        r = append_tmpfs_mounts(&ml, p->temporary_filesystems, p->n_temporary_filesystems);
        if (r < 0)
                return r;

        if (p->tmp_dir) {
                bool ro = streq(p->tmp_dir, RUN_SYSTEMD_EMPTY);

                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/tmp",
                        .mode = ro ? MOUNT_PRIVATE_TMP_READ_ONLY : MOUNT_PRIVATE_TMP,
                        .source_const = p->tmp_dir,
                };
        }

        if (p->var_tmp_dir) {
                bool ro = streq(p->var_tmp_dir, RUN_SYSTEMD_EMPTY);

                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/var/tmp",
                        .mode = ro ? MOUNT_PRIVATE_TMP_READ_ONLY : MOUNT_PRIVATE_TMP,
                        .source_const = p->var_tmp_dir,
                };
        }

        r = append_mount_images(&ml, p->mount_images, p->n_mount_images);
        if (r < 0)
                return r;

        r = append_extensions(&ml, root, p->extension_dir, hierarchies, p->extension_images, p->n_extension_images, p->extension_directories);
        if (r < 0)
                return r;

        if (p->private_dev) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/dev",
                        .mode = MOUNT_PRIVATE_DEV,
                        .flags = DEV_MOUNT_OPTIONS,
                };
        }

        /* In case /proc is successfully mounted with pid tree subset only (ProcSubset=pid), the protective
           mounts to non-pid /proc paths would fail. But the pid only option may have failed gracefully, so
           let's try the mounts but it's not fatal if they don't succeed. */
        bool ignore_protect_proc = p->ignore_protect_paths || p->proc_subset == PROC_SUBSET_PID;
        if (p->protect_kernel_tunables) {
                r = append_static_mounts(&ml,
                                         protect_kernel_tunables_proc_table,
                                         ELEMENTSOF(protect_kernel_tunables_proc_table),
                                         ignore_protect_proc);
                if (r < 0)
                        return r;

                r = append_static_mounts(&ml,
                                         protect_kernel_tunables_sys_table,
                                         ELEMENTSOF(protect_kernel_tunables_sys_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        if (p->protect_kernel_modules) {
                r = append_static_mounts(&ml,
                                         protect_kernel_modules_table,
                                         ELEMENTSOF(protect_kernel_modules_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        if (p->protect_kernel_logs) {
                r = append_static_mounts(&ml,
                                         protect_kernel_logs_proc_table,
                                         ELEMENTSOF(protect_kernel_logs_proc_table),
                                         ignore_protect_proc);
                if (r < 0)
                        return r;

                r = append_static_mounts(&ml,
                                         protect_kernel_logs_dev_table,
                                         ELEMENTSOF(protect_kernel_logs_dev_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        if (p->protect_control_groups) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/sys/fs/cgroup",
                        .mode = MOUNT_READ_ONLY,
                };
        }

        r = append_protect_home(&ml, p->protect_home, p->ignore_protect_paths);
        if (r < 0)
                return r;

        r = append_protect_system(&ml, p->protect_system, false);
        if (r < 0)
                return r;

        if (namespace_parameters_mount_apivfs(p)) {
                r = append_static_mounts(&ml,
                                         apivfs_table,
                                         ELEMENTSOF(apivfs_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        /* Note, if proc is mounted with subset=pid then neither of the two paths will exist, i.e. they are
         * implicitly protected by the mount option. */
        if (p->protect_hostname) {
                r = append_static_mounts(
                                &ml,
                                protect_hostname_table,
                                ELEMENTSOF(protect_hostname_table),
                                ignore_protect_proc);
                if (r < 0)
                        return r;
        }

        if (p->private_network) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/sys",
                        .mode = MOUNT_PRIVATE_SYSFS,
                };
        }

        if (p->private_ipc) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/dev/mqueue",
                        .mode = MOUNT_MQUEUEFS,
                        .flags = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
                };
        }

        if (p->creds_path) {
                /* If our service has a credentials store configured, then bind that one in, but hide
                 * everything else. */

                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/run/credentials",
                        .mode = MOUNT_TMPFS,
                        .read_only = true,
                        .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST,
                        .flags = MS_NODEV|MS_STRICTATIME|MS_NOSUID|MS_NOEXEC,
                };

                me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = p->creds_path,
                        .mode = MOUNT_BIND,
                        .read_only = true,
                        .source_const = p->creds_path,
                        .ignore = true,
                };
        } else {
                /* If our service has no credentials store configured, then make the whole credentials tree
                 * inaccessible wholesale. */

                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/run/credentials",
                        .mode = MOUNT_INACCESSIBLE,
                        .ignore = true,
                };
        }

        if (p->log_namespace) {
                _cleanup_free_ char *q = NULL;

                q = strjoin("/run/systemd/journal.", p->log_namespace);
                if (!q)
                        return log_oom_debug();

                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/run/systemd/journal",
                        .mode = MOUNT_BIND_RECURSIVE,
                        .read_only = true,
                        .source_malloc = TAKE_PTR(q),
                };
        }

        /* Will be used to add bind mounts at runtime */
        if (setup_propagate) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .source_const = p->propagate_dir,
                        .path_const = p->incoming_dir,
                        .mode = MOUNT_BIND,
                        .read_only = true,
                };
        }

        if (p->notify_socket) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = p->notify_socket,
                        .source_const = p->notify_socket,
                        .mode = MOUNT_BIND,
                        .read_only = true,
                };
        }

        if (p->host_os_release_stage) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/run/host/.os-release-stage/",
                        .source_const = p->host_os_release_stage,
                        .mode = MOUNT_BIND,
                        .read_only = true,
                        .ignore = true, /* Live copy, don't hard-fail if it goes missing */
                };
        }

        /* Prepend the root directory where that's necessary */
        r = prefix_where_needed(&ml, root);
        if (r < 0)
                return r;

        drop_unused_mounts(&ml, root);

        /* All above is just preparation, figuring out what to do. Let's now actually start doing something. */

        if (unshare(CLONE_NEWNS) < 0) {
                r = log_debug_errno(errno, "Failed to unshare the mount namespace: %m");

                if (ERRNO_IS_PRIVILEGE(r) ||
                    ERRNO_IS_NOT_SUPPORTED(r))
                        /* If the kernel doesn't support namespaces, or when there's a MAC or seccomp filter
                         * in place that doesn't allow us to create namespaces (or a missing cap), then
                         * propagate a recognizable error back, which the caller can use to detect this case
                         * (and only this) and optionally continue without namespacing applied. */
                        return -ENOANO;

                return r;
        }

        /* Create the source directory to allow runtime propagation of mounts */
        if (setup_propagate)
                (void) mkdir_p(p->propagate_dir, 0600);

        if (p->n_extension_images > 0 || !strv_isempty(p->extension_directories))
                /* ExtensionImages/Directories mountpoint directories will be created while parsing the
                 * mounts to create, so have the parent ready */
                (void) mkdir_p(p->extension_dir, 0600);

        /* Remount / as SLAVE so that nothing now mounted in the namespace
         * shows up in the parent */
        if (mount(NULL, "/", NULL, MS_SLAVE|MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to remount '/' as SLAVE: %m");

        if (p->root_image) {
                /* A root image is specified, mount it to the right place */
                r = dissected_image_mount(
                                dissected_image,
                                root,
                                /* uid_shift= */ UID_INVALID,
                                /* uid_range= */ UID_INVALID,
                                /* userns_fd= */ -EBADF,
                                dissect_image_flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to mount root image: %m");

                /* Now release the block device lock, so that udevd is free to call BLKRRPART on the device
                 * if it likes. */
                r = loop_device_flock(loop_device, LOCK_UN);
                if (r < 0)
                        return log_debug_errno(r, "Failed to release lock on loopback block device: %m");

                r = dissected_image_relinquish(dissected_image);
                if (r < 0)
                        return log_debug_errno(r, "Failed to relinquish dissected image: %m");

        } else if (p->root_directory) {

                /* A root directory is specified. Turn its directory into bind mount, if it isn't one yet. */
                r = path_is_mount_point(root, NULL, AT_SYMLINK_FOLLOW);
                if (r < 0)
                        return log_debug_errno(r, "Failed to detect that %s is a mount point or not: %m", root);
                if (r == 0) {
                        r = mount_nofollow_verbose(LOG_DEBUG, root, root, NULL, MS_BIND|MS_REC, NULL);
                        if (r < 0)
                                return r;
                }

        } else {
                /* Let's mount the main root directory to the root directory to use */
                r = mount_nofollow_verbose(LOG_DEBUG, "/", root, NULL, MS_BIND|MS_REC, NULL);
                if (r < 0)
                        return r;
        }

        /* Try to set up the new root directory before mounting anything else there. */
        if (p->root_image || p->root_directory)
                (void) base_filesystem_create(root, UID_INVALID, GID_INVALID);

        /* Now make the magic happen */
        r = apply_mounts(&ml, root, p, error_path);
        if (r < 0)
                return r;

        /* MS_MOVE does not work on MS_SHARED so the remount MS_SHARED will be done later */
        r = mount_switch_root(root, /* mount_propagation_flag = */ 0);
        if (r == -EINVAL && p->root_directory) {
                /* If we are using root_directory and we don't have privileges (ie: user manager in a user
                 * namespace) and the root_directory is already a mount point in the parent namespace,
                 * MS_MOVE will fail as we don't have permission to change it (with EINVAL rather than
                 * EPERM). Attempt to bind-mount it over itself (like we do above if it's not already a
                 * mount point) and try again. */
                r = mount_nofollow_verbose(LOG_DEBUG, root, root, NULL, MS_BIND|MS_REC, NULL);
                if (r < 0)
                        return r;
                r = mount_switch_root(root, /* mount_propagation_flag = */ 0);
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to mount root with MS_MOVE: %m");

        /* Remount / as the desired mode. Note that this will not reestablish propagation from our side to
         * the host, since what's disconnected is disconnected. */
        if (mount(NULL, "/", NULL, mount_propagation_flag | MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to remount '/' with desired mount flags: %m");

        /* bind_mount_in_namespace() will MS_MOVE into that directory, and that's only supported for
         * non-shared mounts. This needs to happen after remounting / or it will fail. */
        if (setup_propagate && mount(NULL, p->incoming_dir, NULL, MS_SLAVE, NULL) < 0)
                return log_debug_errno(errno, "Failed to remount %s with MS_SLAVE: %m", p->incoming_dir);

        return 0;
}

void bind_mount_free_many(BindMount *b, size_t n) {
        assert(b || n == 0);

        for (size_t i = 0; i < n; i++) {
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

        c[(*n)++] = (BindMount) {
                .source = TAKE_PTR(s),
                .destination = TAKE_PTR(d),
                .read_only = item->read_only,
                .nosuid = item->nosuid,
                .recursive = item->recursive,
                .ignore_enoent = item->ignore_enoent,
        };

        return 0;
}

MountImage* mount_image_free_many(MountImage *m, size_t *n) {
        assert(n);
        assert(m || *n == 0);

        for (size_t i = 0; i < *n; i++) {
                free(m[i].source);
                free(m[i].destination);
                mount_options_free_all(m[i].mount_options);
        }

        free(m);
        *n = 0;
        return NULL;
}

int mount_image_add(MountImage **m, size_t *n, const MountImage *item) {
        _cleanup_free_ char *s = NULL, *d = NULL;
        _cleanup_(mount_options_free_allp) MountOptions *options = NULL;
        MountImage *c;

        assert(m);
        assert(n);
        assert(item);

        s = strdup(item->source);
        if (!s)
                return -ENOMEM;

        if (item->destination) {
                d = strdup(item->destination);
                if (!d)
                        return -ENOMEM;
        }

        LIST_FOREACH(mount_options, i, item->mount_options) {
                _cleanup_(mount_options_free_allp) MountOptions *o = NULL;

                o = new(MountOptions, 1);
                if (!o)
                        return -ENOMEM;

                *o = (MountOptions) {
                        .partition_designator = i->partition_designator,
                        .options = strdup(i->options),
                };
                if (!o->options)
                        return -ENOMEM;

                LIST_APPEND(mount_options, options, TAKE_PTR(o));
        }

        c = reallocarray(*m, *n + 1, sizeof(MountImage));
        if (!c)
                return -ENOMEM;

        *m = c;

        c[(*n)++] = (MountImage) {
                .source = TAKE_PTR(s),
                .destination = TAKE_PTR(d),
                .mount_options = TAKE_PTR(options),
                .ignore_enoent = item->ignore_enoent,
                .type = item->type,
        };

        return 0;
}

void temporary_filesystem_free_many(TemporaryFileSystem *t, size_t n) {
        assert(t || n == 0);

        for (size_t i = 0; i < n; i++) {
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

        c[(*n)++] = (TemporaryFileSystem) {
                .path = TAKE_PTR(p),
                .options = TAKE_PTR(o),
        };

        return 0;
}

static int make_tmp_prefix(const char *prefix) {
        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* Don't do anything unless we know the dir is actually missing */
        r = access(prefix, F_OK);
        if (r >= 0)
                return 0;
        if (errno != ENOENT)
                return -errno;

        WITH_UMASK(000)
                r = mkdir_parents(prefix, 0755);
        if (r < 0)
                return r;

        r = tempfn_random(prefix, NULL, &t);
        if (r < 0)
                return r;

        /* umask will corrupt this access mode, but that doesn't matter, we need to call chmod() anyway for
         * the suid bit, below. */
        fd = open_mkdir_at(AT_FDCWD, t, O_EXCL|O_CLOEXEC, 0777);
        if (fd < 0)
                return fd;

        r = RET_NERRNO(fchmod(fd, 01777));
        if (r < 0) {
                (void) rmdir(t);
                return r;
        }

        r = RET_NERRNO(rename(t, prefix));
        if (r < 0) {
                (void) rmdir(t);
                return r == -EEXIST ? 0 : r; /* it's fine if someone else created the dir by now */
        }

        return 0;

}

static int setup_one_tmp_dir(const char *id, const char *prefix, char **path, char **tmp_path) {
        _cleanup_free_ char *x = NULL;
        _cleanup_free_ char *y = NULL;
        sd_id128_t boot_id;
        bool rw = true;
        int r;

        assert(id);
        assert(prefix);
        assert(path);

        /* We include the boot id in the directory so that after a
         * reboot we can easily identify obsolete directories. */

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        x = strjoin(prefix, "/systemd-private-", SD_ID128_TO_STRING(boot_id), "-", id, "-XXXXXX");
        if (!x)
                return -ENOMEM;

        r = make_tmp_prefix(prefix);
        if (r < 0)
                return r;

        WITH_UMASK(0077)
                if (!mkdtemp(x)) {
                        if (errno == EROFS || ERRNO_IS_DISK_SPACE(errno))
                                rw = false;
                        else
                                return -errno;
                }

        if (rw) {
                y = strjoin(x, "/tmp");
                if (!y)
                        return -ENOMEM;

                WITH_UMASK(0000)
                        if (mkdir(y, 0777 | S_ISVTX) < 0)
                                return -errno;

                r = label_fix_full(AT_FDCWD, y, prefix, 0);
                if (r < 0)
                        return r;

                if (tmp_path)
                        *tmp_path = TAKE_PTR(y);
        } else {
                /* Trouble: we failed to create the directory. Instead of failing, let's simulate /tmp being
                 * read-only. This way the service will get the EROFS result as if it was writing to the real
                 * file system. */
                WITH_UMASK(0000)
                        r = mkdir_p(RUN_SYSTEMD_EMPTY, 0500);
                if (r < 0)
                        return r;

                r = free_and_strdup(&x, RUN_SYSTEMD_EMPTY);
                if (r < 0)
                        return r;
        }

        *path = TAKE_PTR(x);
        return 0;
}

int setup_tmp_dirs(const char *id, char **tmp_dir, char **var_tmp_dir) {
        _cleanup_(namespace_cleanup_tmpdirp) char *a = NULL;
        _cleanup_(rmdir_and_freep) char *a_tmp = NULL;
        char *b;
        int r;

        assert(id);
        assert(tmp_dir);
        assert(var_tmp_dir);

        r = setup_one_tmp_dir(id, "/tmp", &a, &a_tmp);
        if (r < 0)
                return r;

        r = setup_one_tmp_dir(id, "/var/tmp", &b, NULL);
        if (r < 0)
                return r;

        a_tmp = mfree(a_tmp); /* avoid rmdir */
        *tmp_dir = TAKE_PTR(a);
        *var_tmp_dir = TAKE_PTR(b);

        return 0;
}

int setup_shareable_ns(int ns_storage_socket[static 2], unsigned long nsflag) {
        _cleanup_close_ int ns = -EBADF;
        int r;
        const char *ns_name, *ns_path;

        assert(ns_storage_socket);
        assert(ns_storage_socket[0] >= 0);
        assert(ns_storage_socket[1] >= 0);

        ns_name = namespace_single_flag_to_string(nsflag);
        assert(ns_name);

        /* We use the passed socketpair as a storage buffer for our
         * namespace reference fd. Whatever process runs this first
         * shall create a new namespace, all others should just join
         * it. To serialize that we use a file lock on the socket
         * pair.
         *
         * It's a bit crazy, but hey, works great! */

        r = posix_lock(ns_storage_socket[0], LOCK_EX);
        if (r < 0)
                return r;

        CLEANUP_POSIX_UNLOCK(ns_storage_socket[0]);

        ns = receive_one_fd(ns_storage_socket[0], MSG_PEEK|MSG_DONTWAIT);
        if (ns >= 0) {
                /* Yay, found something, so let's join the namespace */
                r = RET_NERRNO(setns(ns, nsflag));
                if (r < 0)
                        return r;

                return 0;
        }

        if (ns != -EAGAIN)
                return ns;

        /* Nothing stored yet, so let's create a new namespace. */

        if (unshare(nsflag) < 0)
                return -errno;

        (void) loopback_setup();

        ns_path = strjoina("/proc/self/ns/", ns_name);
        ns = open(ns_path, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (ns < 0)
                return -errno;

        r = send_one_fd(ns_storage_socket[1], ns, MSG_DONTWAIT);
        if (r < 0)
                return r;

        return 1;
}

int open_shareable_ns_path(int ns_storage_socket[static 2], const char *path, unsigned long nsflag) {
        _cleanup_close_ int ns = -EBADF;
        int r;

        assert(ns_storage_socket);
        assert(ns_storage_socket[0] >= 0);
        assert(ns_storage_socket[1] >= 0);
        assert(path);

        /* If the storage socket doesn't contain a ns fd yet, open one via the file system and store it in
         * it. This is supposed to be called ahead of time, i.e. before setup_shareable_ns() which will
         * allocate a new anonymous ns if needed. */

        r = posix_lock(ns_storage_socket[0], LOCK_EX);
        if (r < 0)
                return r;

        CLEANUP_POSIX_UNLOCK(ns_storage_socket[0]);

        ns = receive_one_fd(ns_storage_socket[0], MSG_PEEK|MSG_DONTWAIT);
        if (ns >= 0)
                return 0;
        if (ns != -EAGAIN)
                return ns;

        /* Nothing stored yet. Open the file from the file system. */

        ns = open(path, O_RDONLY|O_NOCTTY|O_CLOEXEC);
        if (ns < 0)
                return -errno;

        r = fd_is_ns(ns, nsflag);
        if (r == 0)
                return -EINVAL;
        if (r < 0 && r != -EUCLEAN) /* EUCLEAN: we don't know */
                return r;

        r = send_one_fd(ns_storage_socket[1], ns, MSG_DONTWAIT);
        if (r < 0)
                return r;

        return 1;
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
        [PROTECT_HOME_NO]        = "no",
        [PROTECT_HOME_YES]       = "yes",
        [PROTECT_HOME_READ_ONLY] = "read-only",
        [PROTECT_HOME_TMPFS]     = "tmpfs",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_home, ProtectHome, PROTECT_HOME_YES);

static const char *const protect_system_table[_PROTECT_SYSTEM_MAX] = {
        [PROTECT_SYSTEM_NO]     = "no",
        [PROTECT_SYSTEM_YES]    = "yes",
        [PROTECT_SYSTEM_FULL]   = "full",
        [PROTECT_SYSTEM_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_system, ProtectSystem, PROTECT_SYSTEM_YES);

static const char* const namespace_type_table[] = {
        [NAMESPACE_MOUNT]  = "mnt",
        [NAMESPACE_CGROUP] = "cgroup",
        [NAMESPACE_UTS]    = "uts",
        [NAMESPACE_IPC]    = "ipc",
        [NAMESPACE_USER]   = "user",
        [NAMESPACE_PID]    = "pid",
        [NAMESPACE_NET]    = "net",
        [NAMESPACE_TIME]   = "time",
};

DEFINE_STRING_TABLE_LOOKUP(namespace_type, NamespaceType);

static const char* const protect_proc_table[_PROTECT_PROC_MAX] = {
        [PROTECT_PROC_DEFAULT]    = "default",
        [PROTECT_PROC_NOACCESS]   = "noaccess",
        [PROTECT_PROC_INVISIBLE]  = "invisible",
        [PROTECT_PROC_PTRACEABLE] = "ptraceable",
};

DEFINE_STRING_TABLE_LOOKUP(protect_proc, ProtectProc);

static const char* const proc_subset_table[_PROC_SUBSET_MAX] = {
        [PROC_SUBSET_ALL] = "all",
        [PROC_SUBSET_PID] = "pid",
};

DEFINE_STRING_TABLE_LOOKUP(proc_subset, ProcSubset);
