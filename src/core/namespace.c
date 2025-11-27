/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/loop.h>
#include <linux/magic.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "base-filesystem.h"
#include "bitfield.h"
#include "chase.h"
#include "cryptsetup-util.h"
#include "dev-setup.h"
#include "devnum-util.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "escape.h"
#include "extension-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "iovec-util.h"
#include "label-util.h"
#include "lock-util.h"
#include "log.h"
#include "loop-util.h"
#include "loopback-setup.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "mstack.h"
#include "namespace.h"
#include "namespace-util.h"
#include "nsflags.h"
#include "nulstr-util.h"
#include "os-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
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
#include "vpick.h"

#define DEV_MOUNT_OPTIONS (MS_NOSUID|MS_STRICTATIME|MS_NOEXEC)

typedef enum MountMode {
        /* This is ordered by priority! */
        MOUNT_INACCESSIBLE,
        MOUNT_OVERLAY,
        MOUNT_IMAGE,
        MOUNT_BIND,
        MOUNT_BIND_RECURSIVE,
        MOUNT_PRIVATE_TMP,
        MOUNT_PRIVATE_DEV,
        MOUNT_BIND_DEV,
        MOUNT_EMPTY_DIR,
        MOUNT_PRIVATE_SYSFS,
        MOUNT_BIND_SYSFS,
        MOUNT_PROCFS,
        MOUNT_PRIVATE_CGROUP2FS,
        MOUNT_READ_ONLY,
        MOUNT_READ_WRITE,
        MOUNT_NOEXEC,
        MOUNT_EXEC,
        MOUNT_TMPFS,
        MOUNT_RUN,
        MOUNT_PRIVATE_TMPFS,       /* Mounted outside the root directory, and used by subsequent mounts */
        MOUNT_EXTENSION_DIRECTORY, /* Bind-mounted outside the root directory, and used by subsequent mounts */
        MOUNT_EXTENSION_IMAGE,     /* Mounted outside the root directory, and used by subsequent mounts */
        MOUNT_MQUEUEFS,
        MOUNT_READ_WRITE_IMPLICIT, /* Should have the lowest priority. */
        MOUNT_BPFFS,               /* Special mount for bpffs, which is mounted with fsmount() and move_mount() */
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
        bool has_prefix:1;        /* Already prefixed by the root dir? */
        bool read_only:1;         /* Shall this mount point be read-only? */
        bool nosuid:1;            /* Shall set MS_NOSUID on the mount itself */
        bool noexec:1;            /* Shall set MS_NOEXEC on the mount itself */
        bool exec:1;              /* Shall clear MS_NOEXEC on the mount itself */
        bool create_source_dir:1; /* Create the source directory if it doesn't exist - for implicit bind mounts */
        mode_t source_dir_mode;   /* Mode for the source directory, if it is to be created */
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
        MountOptions *image_options_const;
        char **overlay_layers;
        VeritySettings verity;
        ImageClass filter_class; /* Used for live updates to skip inapplicable images */
        bool idmapped;
        uid_t idmap_uid;
        gid_t idmap_gid;
} MountEntry;

typedef struct MountList {
        MountEntry *mounts;
        size_t n_mounts;
} MountList;

static const BindMount bind_log_sockets_table[] = {
        { (char*) "/run/systemd/journal/socket",  (char*) "/run/systemd/journal/socket",  .read_only = true, .nosuid = true, .noexec = true, .nodev = true, .ignore_enoent = true },
        { (char*) "/run/systemd/journal/stdout",  (char*) "/run/systemd/journal/stdout",  .read_only = true, .nosuid = true, .noexec = true, .nodev = true, .ignore_enoent = true },
        { (char*) "/run/systemd/journal/dev-log", (char*) "/run/systemd/journal/dev-log", .read_only = true, .nosuid = true, .noexec = true, .nodev = true, .ignore_enoent = true },
};

/* If MountAPIVFS= is used, let's mount /proc/, /dev/, /sys/, and /run/, but only as a fallback if the user
 * hasn't mounted something already. These mounts are hence overridden by any other explicitly configured
 * mounts. */
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
        { "/sys/fs/cgroup",      MOUNT_READ_WRITE_IMPLICIT, false }, /* READ_ONLY is set by ProtectControlGroups= option */
        { "/sys/fs/selinux",     MOUNT_READ_WRITE_IMPLICIT, true  },
        { "/sys/kernel/debug",   MOUNT_READ_ONLY,           true  },
        { "/sys/kernel/tracing", MOUNT_READ_ONLY,           true  },
};

/* PrivateBPF= option */
static const MountEntry private_bpf_no_table[] = {
        { "/sys/fs/bpf",         MOUNT_READ_ONLY,    true  },
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
 * ProtectHome=read-only. Protect $HOME and $XDG_RUNTIME_DIR and rest of
 * system should be protected by ProtectSystem=.
 */
static const MountEntry protect_home_read_only_table[] = {
        { "/home",               MOUNT_READ_ONLY,     true  },
        { "/run/user",           MOUNT_READ_ONLY,     true  },
        { "/root",               MOUNT_READ_ONLY,     true  },
};

/* ProtectHome=tmpfs */
static const MountEntry protect_home_tmpfs_table[] = {
        { "/home",               MOUNT_TMPFS,        true, .read_only = true, .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST, .flags = MS_NODEV|MS_STRICTATIME },
        { "/run/user",           MOUNT_TMPFS,        true, .read_only = true, .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST, .flags = MS_NODEV|MS_STRICTATIME },
        { "/root",               MOUNT_TMPFS,        true, .read_only = true, .options_const = "mode=0700" TMPFS_LIMITS_EMPTY_OR_ALMOST, .flags = MS_NODEV|MS_STRICTATIME },
};

/* ProtectHome=yes */
static const MountEntry protect_home_yes_table[] = {
        { "/home",               MOUNT_INACCESSIBLE, true  },
        { "/run/user",           MOUNT_INACCESSIBLE, true  },
        { "/root",               MOUNT_INACCESSIBLE, true  },
};

/* ProtectControlGroups=yes */
static const MountEntry protect_control_groups_yes_table[] = {
        { "/sys/fs/cgroup",      MOUNT_READ_ONLY,         false  },
};

/* ProtectControlGroups=private. Note mount_private_apivfs() always use MS_NOSUID|MS_NOEXEC|MS_NODEV so
 * flags are not set here. */
static const MountEntry protect_control_groups_private_table[] = {
        { "/sys/fs/cgroup",      MOUNT_PRIVATE_CGROUP2FS, false, .read_only = false },
};

/* ProtectControlGroups=strict */
static const MountEntry protect_control_groups_strict_table[] = {
        { "/sys/fs/cgroup",      MOUNT_PRIVATE_CGROUP2FS, false, .read_only = true },
};

/* ProtectSystem=yes */
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

/* ProtectSystem=strict. In this strict mode, we mount everything read-only, except for /proc, /dev, and
 * /sys which are the kernel API VFS and left writable. PrivateDevices= + ProtectKernelTunables=
 * protect those, and these options should be fully orthogonal. (And of course /home and friends are also
 * left writable, as ProtectHome= shall manage those, orthogonally).
 */
static const MountEntry protect_system_strict_table[] = {
        { "/",                   MOUNT_READ_ONLY,           false },
        { "/proc",               MOUNT_READ_WRITE_IMPLICIT, false },      /* ProtectKernelTunables= */
        { "/sys",                MOUNT_READ_WRITE_IMPLICIT, false },      /* ProtectKernelTunables= */
        { "/dev",                MOUNT_READ_WRITE_IMPLICIT, false },      /* PrivateDevices= */
        { "/home",               MOUNT_READ_WRITE_IMPLICIT, true  },      /* ProtectHome= */
        { "/run/user",           MOUNT_READ_WRITE_IMPLICIT, true  },      /* ProtectHome= */
        { "/root",               MOUNT_READ_WRITE_IMPLICIT, true  },      /* ProtectHome= */
};

/* ProtectHostname=yes */
static const MountEntry protect_hostname_yes_table[] = {
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
        [MOUNT_PRIVATE_DEV]           = "private-dev",
        [MOUNT_BIND_DEV]              = "bind-dev",
        [MOUNT_EMPTY_DIR]             = "empty-dir",
        [MOUNT_PRIVATE_SYSFS]         = "private-sysfs",
        [MOUNT_BIND_SYSFS]            = "bind-sysfs",
        [MOUNT_PRIVATE_CGROUP2FS]     = "private-cgroup2fs",
        [MOUNT_PROCFS]                = "procfs",
        [MOUNT_READ_ONLY]             = "read-only",
        [MOUNT_READ_WRITE]            = "read-write",
        [MOUNT_NOEXEC]                = "noexec",
        [MOUNT_EXEC]                  = "exec",
        [MOUNT_TMPFS]                 = "tmpfs",
        [MOUNT_RUN]                   = "run",
        [MOUNT_PRIVATE_TMPFS]         = "private-tmpfs",
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

static const char* mount_entry_path(const MountEntry *p) {
        assert(p);

        /* Returns the path of this bind mount. If the malloc()-allocated ->path_buffer field is set we return that,
         * otherwise the stack/static ->path field is returned. */

        return p->path_malloc ?: p->path_const;
}

static const char* mount_entry_unprefixed_path(const MountEntry *p) {
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

        return p->read_only || IN_SET(p->mode, MOUNT_READ_ONLY, MOUNT_INACCESSIBLE);
}

static bool mount_entry_noexec(const MountEntry *p) {
        assert(p);

        return p->noexec || IN_SET(p->mode, MOUNT_NOEXEC, MOUNT_INACCESSIBLE, MOUNT_PRIVATE_SYSFS, MOUNT_BIND_SYSFS, MOUNT_PROCFS, MOUNT_PRIVATE_CGROUP2FS);
}

static bool mount_entry_exec(const MountEntry *p) {
        assert(p);

        return p->exec || p->mode == MOUNT_EXEC;
}

static const char* mount_entry_source(const MountEntry *p) {
        assert(p);

        return p->source_malloc ?: p->source_const;
}

static const char* mount_entry_options(const MountEntry *p) {
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
        verity_settings_done(&p->verity);
}

static void mount_list_done(MountList *ml) {
        assert(ml);

        FOREACH_ARRAY(m, ml->mounts, ml->n_mounts)
                mount_entry_done(m);

        ml->mounts = mfree(ml->mounts);
        ml->n_mounts = 0;
}

static MountEntry* mount_list_extend(MountList *ml) {
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
                        .noexec = b->noexec,
                        .flags = b->nodev ? MS_NODEV : 0,
                        .source_const = b->source,
                        .ignore = b->ignore_enoent,
                        .idmapped = b->idmapped,
                        .idmap_uid = b->uid,
                        .idmap_gid = b->gid,
                };
        }

        return 0;
}

static int append_mount_images(MountList *ml, const MountImage *mount_images, size_t n) {
        int r;

        assert(ml);
        assert(mount_images || n == 0);

        FOREACH_ARRAY(m, mount_images, n) {
                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                r = verity_settings_load(&verity, m->source, /* root_hash_path= */ NULL, /* root_hash_sig_path= */ NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to check verity root hash of %s: %m", m->source);

                *me = (MountEntry) {
                        .path_const = m->destination,
                        .mode = MOUNT_IMAGE,
                        .source_const = m->source,
                        .image_options_const = m->mount_options,
                        .ignore = m->ignore_enoent,
                        .verity = TAKE_GENERIC(verity, VeritySettings, VERITY_SETTINGS_DEFAULT),
                        .filter_class = _IMAGE_CLASS_INVALID,
                };
        }

        return 0;
}

static int append_extensions(
                MountList *ml,
                const char *root,
                const char *private_namespace_dir,
                char **hierarchies,
                const MountImage *mount_images,
                size_t n_mount_images,
                char **extension_directories) {

        char ***overlays = NULL;
        size_t n_overlays = 0;
        int r;

        assert(ml);

        if (n_mount_images == 0 && strv_isempty(extension_directories))
                return 0;

        assert(private_namespace_dir);

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
        for (size_t i = 0; i < n_mount_images; i++) {
                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;
                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                _cleanup_free_ char *mount_point = NULL;
                const MountImage *m = mount_images + i;

                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              m->source,
                              pick_filter_image_raw,
                              ELEMENTSOF(pick_filter_image_raw),
                              PICK_ARCHITECTURE|PICK_TRIES,
                              &result);
                if (r == -ENOENT && m->ignore_enoent)
                        continue;
                if (r < 0)
                        return r;
                if (!result.path) {
                        if (m->ignore_enoent)
                                continue;

                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOENT),
                                        "No matching entry in .v/ directory %s found.",
                                        m->source);
                }

                r = verity_settings_load(&verity, result.path, /* root_hash_path= */ NULL, /* root_hash_sig_path= */ NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to check verity root hash of %s: %m", result.path);

                if (asprintf(&mount_point, "%s/unit-extensions/%zu", private_namespace_dir, i) < 0)
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
                        .source_malloc = TAKE_PTR(result.path),
                        .mode = MOUNT_EXTENSION_IMAGE,
                        .has_prefix = true,
                        .verity = TAKE_GENERIC(verity, VeritySettings, VERITY_SETTINGS_DEFAULT),
                        .filter_class = _IMAGE_CLASS_INVALID,
                };
        }

        /* Secondly, extend the lowerdir= parameters with each ExtensionDirectory.
         * Bind mount them in the same location as the ExtensionImages, so that we
         * can check that they are valid trees (extension-release.d). */
        STRV_FOREACH(extension_directory, extension_directories) {
                _cleanup_(pick_result_done) PickResult result = PICK_RESULT_NULL;
                _cleanup_free_ char *mount_point = NULL;
                const char *e = *extension_directory;
                bool ignore_enoent = false;

                /* Look for any prefixes */
                if (startswith(e, "-")) {
                        e++;
                        ignore_enoent = true;
                }
                /* Ignore this for now */
                if (startswith(e, "+"))
                        e++;

                r = path_pick(/* toplevel_path= */ NULL,
                              /* toplevel_fd= */ AT_FDCWD,
                              e,
                              pick_filter_image_dir,
                              ELEMENTSOF(pick_filter_image_dir),
                              PICK_ARCHITECTURE|PICK_TRIES,
                              &result);
                if (r == -ENOENT && ignore_enoent)
                        continue;
                if (r < 0)
                        return r;
                if (!result.path) {
                        if (ignore_enoent)
                                continue;

                        return log_debug_errno(
                                        SYNTHETIC_ERRNO(ENOENT),
                                        "No matching entry in .v/ directory %s found.",
                                        e);
                }

                /* Pick up the counter where the ExtensionImages left it. */
                if (asprintf(&mount_point, "%s/unit-extensions/%zu", private_namespace_dir, n_mount_images++) < 0)
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
                        .source_malloc = TAKE_PTR(result.path),
                        .mode = MOUNT_EXTENSION_DIRECTORY,
                        .ignore = ignore_enoent,
                        .has_prefix = true,
                        .read_only = true,
                        .filter_class = _IMAGE_CLASS_INVALID,
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
                flags &= ~MS_RDONLY;

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

static int append_private_tmp(MountList *ml, const NamespaceParameters *p) {
        MountEntry *me;

        assert(ml);
        assert(p);
        assert(p->private_tmp == p->private_var_tmp ||
               (p->private_tmp == PRIVATE_TMP_DISCONNECTED && p->private_var_tmp == PRIVATE_TMP_NO));

        if (p->tmp_dir) {
                assert(p->private_tmp == PRIVATE_TMP_CONNECTED);

                me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();
                *me = (MountEntry) {
                        .path_const = "/tmp/",
                        .mode = MOUNT_PRIVATE_TMP,
                        .read_only = streq(p->tmp_dir, RUN_SYSTEMD_EMPTY),
                        .source_const = p->tmp_dir,
                };
        }

        if (p->var_tmp_dir) {
                assert(p->private_var_tmp == PRIVATE_TMP_CONNECTED);

                me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();
                *me = (MountEntry) {
                        .path_const = "/var/tmp/",
                        .mode = MOUNT_PRIVATE_TMP,
                        .read_only = streq(p->var_tmp_dir, RUN_SYSTEMD_EMPTY),
                        .source_const = p->var_tmp_dir,
                };
        }

        if (p->private_tmp != PRIVATE_TMP_DISCONNECTED)
                return 0;

        if (p->private_var_tmp == PRIVATE_TMP_NO) {
                me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();
                *me = (MountEntry) {
                        .path_const = "/tmp/",
                        .mode = MOUNT_PRIVATE_TMPFS,
                        .options_const = "mode=0700" NESTED_TMPFS_LIMITS,
                        .flags = MS_NODEV|MS_STRICTATIME,
                };

                return 0;
        }

        _cleanup_free_ char *tmpfs_dir = NULL, *tmp_dir = NULL, *var_tmp_dir = NULL;
        tmpfs_dir = path_join(p->private_namespace_dir, "unit-private-tmp");
        tmp_dir = path_join(tmpfs_dir, "tmp");
        var_tmp_dir = path_join(tmpfs_dir, "var-tmp");
        if (!tmpfs_dir || !tmp_dir || !var_tmp_dir)
                return log_oom_debug();

        me = mount_list_extend(ml);
        if (!me)
                return log_oom_debug();
        *me = (MountEntry) {
                .path_malloc = TAKE_PTR(tmpfs_dir),
                .mode = MOUNT_PRIVATE_TMPFS,
                .options_const = "mode=0700" NESTED_TMPFS_LIMITS,
                .flags = MS_NODEV|MS_STRICTATIME,
                .has_prefix = true,
        };

        me = mount_list_extend(ml);
        if (!me)
                return log_oom_debug();
        *me = (MountEntry) {
                .source_malloc = TAKE_PTR(tmp_dir),
                .path_const = "/tmp/",
                .mode = MOUNT_BIND,
                .source_dir_mode = 01777,
                .create_source_dir = true,
        };

        me = mount_list_extend(ml);
        if (!me)
                return log_oom_debug();
        *me = (MountEntry) {
                .source_malloc = TAKE_PTR(var_tmp_dir),
                .path_const = "/var/tmp/",
                .mode = MOUNT_BIND,
                .source_dir_mode = 01777,
                .create_source_dir = true,
        };

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

                /* No dynamic values allowed. */
                assert(m->path_const);
                assert(!m->path_malloc);
                assert(!m->unprefixed_path_malloc);
                assert(!m->source_malloc);
                assert(!m->options_malloc);
                assert(!m->overlay_layers);

                *me = *m;
                me->ignore = me->ignore || ignore_protect;
        }

        return 0;
}

static int append_protect_control_groups(MountList *ml, ProtectControlGroups protect_control_groups, bool ignore_protect) {
        assert(ml);

        switch (protect_control_groups) {

        case PROTECT_CONTROL_GROUPS_NO:
                return 0;

        case PROTECT_CONTROL_GROUPS_YES:
                return append_static_mounts(ml, protect_control_groups_yes_table, ELEMENTSOF(protect_control_groups_yes_table), ignore_protect);

        case PROTECT_CONTROL_GROUPS_PRIVATE:
                return append_static_mounts(ml, protect_control_groups_private_table, ELEMENTSOF(protect_control_groups_private_table), ignore_protect);

        case PROTECT_CONTROL_GROUPS_STRICT:
                return append_static_mounts(ml, protect_control_groups_strict_table, ELEMENTSOF(protect_control_groups_strict_table), ignore_protect);

        default:
                assert_not_reached();
        }
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

static int append_private_bpf(
                MountList *ml,
                PrivateBPF private_bpf,
                bool protect_kernel_tunables,
                bool ignore_protect,
                const NamespaceParameters *p) {

        assert(ml);

        switch (private_bpf) {
        case PRIVATE_BPF_NO:
                if (protect_kernel_tunables)
                        return append_static_mounts(ml, private_bpf_no_table, ELEMENTSOF(private_bpf_no_table), ignore_protect);
                return 0;
        case PRIVATE_BPF_YES: {
                MountEntry *me = mount_list_extend(ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = "/sys/fs/bpf",
                        .mode = MOUNT_BPFFS,
                        .ignore = !protect_kernel_tunables, /* indicate whether we should fall back to MOUNT_READ_ONLY on failure. */
                };
                return 0;
        }
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

        /* MOUNT_PRIVATE_TMPFS needs to be set up earlier, especially than MOUNT_BIND. */
        d = -CMP(a->mode == MOUNT_PRIVATE_TMPFS, b->mode == MOUNT_PRIVATE_TMPFS);
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

static bool verity_has_later_duplicates(MountList *ml, const MountEntry *needle) {

        assert(ml);
        assert(needle);
        assert(needle >= ml->mounts && needle < ml->mounts + ml->n_mounts);
        assert(needle->mode == MOUNT_EXTENSION_IMAGE);

        if (!iovec_is_set(&needle->verity.root_hash))
                return false;

        /* Overlayfs rejects supplying the same directory inode twice as determined by filesystem UUID and
         * file handle in lowerdir=, even if they are mounted on different paths, as it resolves each mount
         * to its source filesystem, so drop duplicates, and keep the last one. This only covers non-DDI
         * verity images. Note that the list is ordered, so we only check for the reminder of the list for
         * each item, rather than the full list from the beginning, as any earlier duplicates will have
         * already been pruned. */

        for (const MountEntry *m = needle + 1; m < ml->mounts + ml->n_mounts; m++) {
                if (m->mode != MOUNT_EXTENSION_IMAGE)
                        continue;
                if (iovec_memcmp(&m->verity.root_hash, &needle->verity.root_hash) == 0)
                        return true;
        }

        return false;
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

                if (f->mode == MOUNT_EXTENSION_IMAGE && verity_has_later_duplicates(ml, f)) {
                        log_debug("Skipping duplicate extension image %s", mount_entry_source(f));
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

                /* ExtensionImages/Directories bases are opened in /run/[user/xyz/]systemd/unit-extensions
                 * on the host, and a private (invisible to the guest) tmpfs instance is mounted on
                 * /run/[user/xyz/]systemd/unit-private-tmp as the storage backend of private /tmp and
                 * /var/tmp. */
                if (!IN_SET(f->mode, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY, MOUNT_PRIVATE_TMPFS) &&
                    !path_startswith(mount_entry_path(f), root_directory)) {
                        log_debug("%s is outside of root directory.", mount_entry_path(f));
                        mount_entry_done(f);
                        continue;
                }

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;
}

static int clone_device_node(const char *node, const char *temporary_mount, bool *make_devnode) {
        _cleanup_free_ char *sl = NULL;
        const char *dn, *bn;
        struct stat st;
        int r;

        assert(node);
        assert(path_is_absolute(node));
        assert(temporary_mount);
        assert(make_devnode);

        if (stat(node, &st) < 0) {
                if (errno == ENOENT) {
                        log_debug_errno(errno, "Device node '%s' to clone does not exist.", node);
                        return -ENXIO;
                }

                return log_debug_errno(errno, "Failed to stat() device node '%s' to clone: %m", node);
        }

        r = stat_verify_device_node(&st);
        if (r < 0)
                return log_debug_errno(r, "Cannot clone device node '%s': %m", node);

        dn = strjoina(temporary_mount, node);

        /* First, try to create device node properly */
        if (*make_devnode) {
                mac_selinux_create_file_prepare(node, st.st_mode);
                r = mknod(dn, st.st_mode, st.st_rdev);
                mac_selinux_create_file_clear();
                if (r >= 0)
                        goto add_symlink;
                if (errno != EPERM)
                        return log_debug_errno(errno, "Failed to mknod '%s': %m", node);

                /* This didn't work, let's not try this again for the next iterations. */
                *make_devnode = false;
        }

        /* We're about to fall back to bind-mounting the device node. So create a dummy bind-mount target.
         * Do not prepare device-node SELinux label (see issue 13762) */
        r = mknod(dn, S_IFREG, 0);
        if (r < 0 && errno != EEXIST)
                return log_debug_errno(errno, "Failed to mknod dummy device node for '%s': %m", node);

        /* Fallback to bind-mounting: The assumption here is that all used device nodes carry standard
         * properties. Specifically, the devices nodes we bind-mount should either be owned by root:root or
         * root:tty (e.g. /dev/tty, /dev/ptmx) and should not carry ACLs. */
        r = mount_nofollow_verbose(LOG_DEBUG, node, dn, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

add_symlink:
        bn = path_startswith(node, "/dev/");
        if (!bn)
                return 0;

        /* Create symlinks like /dev/char/1:9 → ../urandom */
        if (asprintf(&sl, "%s/dev/%s/" DEVNUM_FORMAT_STR,
                     temporary_mount,
                     S_ISCHR(st.st_mode) ? "char" : "block",
                     DEVNUM_FORMAT_VAL(st.st_rdev)) < 0)
                return log_oom_debug();

        (void) mkdir_parents(sl, 0755);

        const char *t = strjoina("../", bn);
        if (symlink(t, sl) < 0)
                log_debug_errno(errno, "Failed to symlink '%s' to '%s', ignoring: %m", t, sl);

        return 0;
}

static int bind_mount_device_dir(const char *temporary_mount, const char *dir) {
        const char *t;

        assert(temporary_mount);
        assert(dir);
        assert(path_is_absolute(dir));

        t = strjoina(temporary_mount, dir);

        (void) mkdir(t, 0755);
        return mount_nofollow_verbose(LOG_DEBUG, dir, t, NULL, MS_BIND, NULL);
}

static char* settle_runtime_dir(RuntimeScope scope) {
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

static int mount_private_dev(const MountEntry *m, const NamespaceParameters *p) {
        static const char devnodes[] =
                "/dev/null\0"
                "/dev/zero\0"
                "/dev/full\0"
                "/dev/random\0"
                "/dev/urandom\0"
                "/dev/tty\0";

        _cleanup_(rmdir_and_freep) char *temporary_mount = NULL;
        _cleanup_(umount_and_rmdir_and_freep) char *dev = NULL;
        bool can_mknod = true;
        int r;

        assert(m);
        assert(p);

        r = create_temporary_mount_point(p->runtime_scope, &temporary_mount);
        if (r < 0)
                return r;

        dev = path_join(temporary_mount, "dev");
        if (!dev)
                return -ENOMEM;

        (void) mkdir(dev, 0755);
        r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", dev, "tmpfs", DEV_MOUNT_OPTIONS, "mode=0755" TMPFS_LIMITS_PRIVATE_DEV);
        if (r < 0)
                return r;

        r = label_fix_full(AT_FDCWD, dev, "/dev", 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to fix label of '%s' as /dev/: %m", dev);

        r = bind_mount_device_dir(temporary_mount, "/dev/pts");
        if (r < 0)
                return r;

        /* /dev/ptmx can either be a device node or a symlink to /dev/pts/ptmx.
         * When /dev/ptmx a device node, /dev/pts/ptmx has 000 permissions making it inaccessible.
         * Thus, in that case make a clone.
         * In nspawn and other containers it will be a symlink, in that case make it a symlink. */
        r = is_symlink("/dev/ptmx");
        if (r < 0)
                return log_debug_errno(r, "Failed to detect whether /dev/ptmx is a symlink or not: %m");
        if (r > 0) {
                const char *devptmx = strjoina(temporary_mount, "/dev/ptmx");
                if (symlink("pts/ptmx", devptmx) < 0)
                        return log_debug_errno(errno, "Failed to create symlink '%s' to pts/ptmx: %m", devptmx);
        } else {
                r = clone_device_node("/dev/ptmx", temporary_mount, &can_mknod);
                if (r < 0)
                        return r;
        }

        r = bind_mount_device_dir(temporary_mount, "/dev/shm");
        if (r < 0)
                return r;

        FOREACH_STRING(d, "/dev/mqueue", "/dev/hugepages")
                (void) bind_mount_device_dir(temporary_mount, d);

        /* We assume /run/systemd/journal/ is available if not changing root, which isn't entirely accurate
         * but shouldn't matter, as either way the user would get ENOENT when accessing /dev/log */
        if (!pinned_resource_is_set(p->rootfs) || p->bind_log_sockets) {
                const char *devlog = strjoina(temporary_mount, "/dev/log");
                if (symlink("/run/systemd/journal/dev-log", devlog) < 0)
                        log_debug_errno(errno,
                                        "Failed to create symlink '%s' to /run/systemd/journal/dev-log, ignoring: %m",
                                        devlog);
        }

        NULSTR_FOREACH(d, devnodes) {
                r = clone_device_node(d, temporary_mount, &can_mknod);
                /* ENXIO means the *source* is not a device file, skip creation in that case */
                if (r < 0 && r != -ENXIO)
                        return r;
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
                return r;
        dev = rmdir_and_free(dev); /* Mount is successfully moved, do not umount() */

        return 1;
}

static int mount_bind_dev(const MountEntry *m) {
        int r;

        assert(m);

        /* Implements the little brother of mount_private_dev(): simply bind mounts the host's /dev into the
         * service's /dev. This is only used when RootDirectory= is set. */

        (void) mkdir_p_label(mount_entry_path(m), 0755);

        r = path_is_mount_point(mount_entry_path(m));
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

        r = path_is_mount_point(mount_entry_path(m));
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

        bool noprivs = false;

        /* First, check if we have enough privileges to mount a new instance. */
        _cleanup_close_ int mount_fd = make_fsmount(
                        LOG_DEBUG,
                        /* what= */ fstype,
                        fstype,
                        MS_NOSUID|MS_NOEXEC|MS_NODEV,
                        opts,
                        /* userns_fd= */ -EBADF);
        if (ERRNO_IS_NEG_PRIVILEGE(mount_fd))
                noprivs = true;
        else if (ERRNO_IS_NEG_NOT_SUPPORTED(mount_fd)) {
                /* Fallback for kernels lacking mount_setattr() */

                // FIXME: This compatibility code path shall be removed once kernel 5.12
                //        becomes the new minimal baseline

                r = create_temporary_mount_point(scope, &temporary_mount);
                if (r < 0)
                        return r;

                r = mount_nofollow_verbose(
                                LOG_DEBUG,
                                fstype,
                                temporary_mount,
                                fstype,
                                MS_NOSUID|MS_NOEXEC|MS_NODEV,
                                opts);
                if (ERRNO_IS_NEG_PRIVILEGE(r))
                        noprivs = true;
                else if (r < 0)
                        return r;
        } else if (mount_fd < 0)
                return log_debug_errno(mount_fd, "Failed to make file system mount: %m");

        (void) mkdir_p_label(entry_path, 0755);

        if (noprivs) {
                /* When we do not have enough privileges to mount a new instance, fall back to use an
                 * existing mount. */

                r = path_is_mount_point(entry_path);
                if (r < 0)
                        return log_debug_errno(r, "Unable to determine whether '%s' is already mounted: %m", entry_path);
                if (r > 0)
                        return 0; /* Use the current mount as is. */

                /* We lack permissions to mount a new instance, and it is not already mounted. But we can
                 * access the host's, so as a final fallback bind-mount it to the destination, as most likely
                 * we are inside a user manager in an unprivileged user namespace. */
                r = mount_nofollow_verbose(LOG_DEBUG, bind_source, entry_path, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL);
                if (r < 0)
                        return r;

                return 1;
        }

        /* OK. We have a new mount instance. Let's clear an existing mount and its submounts. */
        r = umount_recursive(entry_path, /* flags= */ 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below '%s', ignoring: %m", entry_path);

        /* Then, move the new mount instance. */
        if (mount_fd >= 0) {
                r = RET_NERRNO(move_mount(mount_fd, "", -EBADF, entry_path, MOVE_MOUNT_F_EMPTY_PATH));
                if (r < 0)
                        return log_debug_errno(r, "Failed to attach '%s' to '%s': %m", fstype, entry_path);
        } else if (temporary_mount) {
                r = mount_nofollow_verbose(LOG_DEBUG, temporary_mount, entry_path, /* fstype= */ NULL, MS_MOVE, /* options= */ NULL);
                if (r < 0)
                        return r;
        } else
                assert_not_reached();

        /* We mounted a new instance now. Let's bind mount the children over now. This matters for nspawn
         * where a bunch of files are overmounted, in particular the boot id. */
        (void) bind_mount_submounts(bind_source, entry_path);
        return 1;
}

static int mount_private_sysfs(const MountEntry *m, const NamespaceParameters *p) {
        assert(m);
        assert(p);
        return mount_private_apivfs("sysfs", mount_entry_path(m), "/sys", /* opts= */ NULL, p->runtime_scope);
}

static int mount_private_cgroup2fs(const MountEntry *m, const NamespaceParameters *p) {
        assert(m);
        assert(p);
        return mount_private_apivfs("cgroup2", mount_entry_path(m), "/sys/fs/cgroup", /* opts= */ NULL, p->runtime_scope);
}

static int mount_procfs(const MountEntry *m, const NamespaceParameters *p) {
        _cleanup_free_ char *opts = NULL;
        int r;

        assert(m);
        assert(p);

        if (p->protect_proc != PROTECT_PROC_DEFAULT ||
            p->proc_subset != PROC_SUBSET_ALL) {

                opts = strjoin("hidepid=",
                               p->protect_proc == PROTECT_PROC_DEFAULT ? "off" : protect_proc_to_string(p->protect_proc));
                if (!opts)
                        return -ENOMEM;

                if (p->proc_subset != PROC_SUBSET_ALL) {
                        r = strextendf_with_separator(&opts, ",", "subset=%s", proc_subset_to_string(p->proc_subset));
                        if (r < 0)
                                return r;
                }
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

        r = path_is_mount_point(mount_entry_path(m));
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
                MountEntry *m,
                const char *root_directory,
                const ImagePolicy *image_policy,
                RuntimeScope runtime_scope) {

        _cleanup_(extension_release_data_done) ExtensionReleaseData rdata = {};
        ImageClass required_class = _IMAGE_CLASS_INVALID;
        int r;

        assert(m);

        if (m->mode == MOUNT_EXTENSION_IMAGE) {
                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &rdata.os_release_id,
                                "ID_LIKE", &rdata.os_release_id_like,
                                "VERSION_ID", &rdata.os_release_version_id,
                                image_class_info[IMAGE_SYSEXT].level_env, &rdata.os_release_sysext_level,
                                image_class_info[IMAGE_CONFEXT].level_env, &rdata.os_release_confext_level,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
                if (isempty(rdata.os_release_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'ID' field not found or empty in 'os-release' data of OS tree '%s'.", empty_to_root(root_directory));

                required_class = m->filter_class;
        }

        r = verity_dissect_and_mount(
                        /* src_fd= */ -EBADF,
                        mount_entry_source(m),
                        mount_entry_path(m),
                        m->image_options_const,
                        image_policy,
                        /* image_filter= */ NULL,
                        &rdata,
                        required_class,
                        &m->verity,
                        runtime_scope,
                        /* ret_image= */ NULL);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r == -ESTALE && rdata.os_release_id)
                return log_error_errno(r, // FIXME: this should not be logged ad LOG_ERR, as it will result in duplicate logging.
                                       "Failed to mount image %s, extension-release metadata does not match the lower layer's: ID=%s ID_LIKE='%s'%s%s%s%s%s%s",
                                       mount_entry_source(m),
                                       rdata.os_release_id,
                                       strempty(rdata.os_release_id_like),
                                       rdata.os_release_version_id ? " VERSION_ID=" : "",
                                       strempty(rdata.os_release_version_id),
                                       rdata.os_release_sysext_level ? image_class_info[IMAGE_SYSEXT].level_env_print : "",
                                       strempty(rdata.os_release_sysext_level),
                                       rdata.os_release_confext_level ? image_class_info[IMAGE_CONFEXT].level_env_print : "",
                                       strempty(rdata.os_release_confext_level));
        if (r == -ENOCSI) {
                log_debug("Image %s does not match the expected class, ignoring", mount_entry_source(m));
                return 0; /* Nothing to do, wrong class */
        }
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

        r = mount_nofollow_verbose(LOG_DEBUG, "systemd-extensions", mount_entry_path(m), "overlay", MS_RDONLY, options);
        if (r == -ENOENT && m->ignore)
                return 0;
        if (r < 0)
                return r;

        return 1;
}

static int mount_bpffs(const MountEntry *m, PidRef *pidref, int socket_fd, int errno_pipe) {
        int r;

        assert(m);
        assert(pidref_is_set(pidref));
        assert(socket_fd >= 0);
        assert(errno_pipe >= 0);

        _cleanup_close_ int fs_fd = fsopen("bpf", FSOPEN_CLOEXEC);
        if (fs_fd < 0)
                return log_debug_errno(errno, "Failed to fsopen: %m");

        r = send_one_fd(socket_fd, fs_fd, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send bpffs fd to child: %m");

        r = pidref_wait_for_terminate_and_check("(sd-bpffs)", pidref, /* flags= */ 0);
        if (r < 0)
                return r;

        /* If something strange happened with the child, let's consider this fatal, too */
        if (r != EXIT_SUCCESS) {
                ssize_t ss = read(errno_pipe, &r, sizeof(r));
                if (ss < 0)
                        return log_debug_errno(errno, "Failed to read from the bpffs helper errno pipe: %m");
                if (ss != sizeof(r))
                        return log_debug_errno(SYNTHETIC_ERRNO(EIO), "Short read from the bpffs helper errno pipe.");
                return log_debug_errno(r, "bpffs helper exited with error: %m");
        }

        pidref_done(pidref);

        _cleanup_close_ int mnt_fd = fsmount(fs_fd, /* flags= */ 0, /* mount_attrs= */ 0);
        if (mnt_fd < 0)
                return log_debug_errno(errno, "Failed to fsmount bpffs: %m");

        r = move_mount(mnt_fd, "", AT_FDCWD, mount_entry_path(m), MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_debug_errno(errno, "Failed to move bpffs mount to %s: %m", mount_entry_path(m));

        return 1;
}

static int follow_symlink(
                const char *root_directory,
                MountEntry *m) {

        _cleanup_free_ char *target = NULL;
        int r;

        assert(m);

        /* Let's chase symlinks, but only one step at a time. That's because depending where the symlink points we
         * might need to change the order in which we mount stuff. Hence: let's normalize piecemeal, and do one step at
         * a time by specifying CHASE_STEP. This function returns 0 if we resolved one step, and > 0 if we reached the
         * end and already have a fully normalized name. */

        r = chase(mount_entry_path(m), root_directory, CHASE_STEP|CHASE_NONEXISTENT|CHASE_TRIGGER_AUTOFS, &target, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to chase symlinks '%s': %m", mount_entry_path(m));
        if (r > 0) /* Reached the end, nothing more to resolve */
                return 1;

        if (m->n_followed >= CHASE_MAX) /* put a boundary on things */
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Symlink loop on '%s'.",
                                       mount_entry_path(m));

        log_debug("Followed mount entry path symlink %s %s %s.",
                  mount_entry_path(m), glyph(GLYPH_ARROW_RIGHT), target);

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

        if (m->mode == MOUNT_BPFFS) {
                r = mount_bpffs(m, p->bpffs_pidref, p->bpffs_socket_fd, p->bpffs_errno_pipe);
                if (r >= 0 ||
                    (!ERRNO_IS_NEG_NOT_SUPPORTED(r) && /* old kernel? */
                     !ERRNO_IS_NEG_PRIVILEGE(r)))      /* ubuntu kernel bug? See issue #38225 */
                        return r;

                if (m->ignore) {
                        log_debug_errno(r, "Failed to mount new bpffs instance, ignoring: %m");
                        return 0;
                }

                log_debug_errno(r, "Failed to mount new bpffs instance at %s, will make read-only, ignoring: %m", mount_entry_path(m));
                m->mode = MOUNT_READ_ONLY;
                m->ignore = true;
        }

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
                                               "File type not supported for inaccessible mounts. Note that symlinks are not allowed.");
                what = inaccessible;
                break;
        }

        case MOUNT_READ_ONLY:
        case MOUNT_READ_WRITE:
        case MOUNT_READ_WRITE_IMPLICIT:
        case MOUNT_EXEC:
        case MOUNT_NOEXEC:
                r = path_is_mount_point_full(mount_entry_path(m), root_directory, /* flags= */ 0);
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
                _cleanup_free_ char *host_os_release_id = NULL, *host_os_release_id_like = NULL,
                                *host_os_release_version_id = NULL, *host_os_release_level = NULL,
                                *extension_name = NULL;
                _cleanup_strv_free_ char **extension_release = NULL;
                ImageClass class = IMAGE_SYSEXT;

                r = path_extract_filename(mount_entry_source(m), &extension_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extract extension name from %s: %m", mount_entry_source(m));

                r = load_extension_release_pairs(
                                mount_entry_source(m),
                                m->filter_class >= 0 ? m->filter_class : IMAGE_SYSEXT,
                                extension_name,
                                /* relax_extension_release_check= */ false,
                                &extension_release);
                if (r == -ENOENT) {
                        if (m->filter_class >= 0)
                                return 0; /* Nothing to do, wrong class */

                        r = load_extension_release_pairs(
                                        mount_entry_source(m),
                                        IMAGE_CONFEXT,
                                        extension_name,
                                        /* relax_extension_release_check= */ false,
                                        &extension_release);
                        if (r >= 0)
                                class = IMAGE_CONFEXT;
                }
                if (r == -ENOENT && m->ignore)
                        return 0;
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'extension-release' data of extension tree %s: %m", mount_entry_source(m));

                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &host_os_release_id,
                                "ID_LIKE", &host_os_release_id_like,
                                "VERSION_ID", &host_os_release_version_id,
                                image_class_info[class].level_env, &host_os_release_level,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
                if (isempty(host_os_release_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'ID' field not found or empty in 'os-release' data of OS tree '%s'.", empty_to_root(root_directory));

                r = extension_release_validate(
                                extension_name,
                                host_os_release_id,
                                host_os_release_id_like,
                                host_os_release_version_id,
                                host_os_release_level,
                                /* host_extension_scope= */ NULL, /* Leave empty, we need to accept both system and portable */
                                extension_release,
                                class);
                if (r < 0)
                        return log_debug_errno(r, "Failed to compare directory %s extension-release metadata with the root's os-release: %m", extension_name);
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Directory %s extension-release metadata does not match the root's.", extension_name);

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

                /* When we create implicit mounts, we might need to create the path ourselves as it is on a
                 * just-created tmpfs, for example. */
                if (m->create_source_dir) {
                        r = mkdir_p(mount_entry_source(m), m->source_dir_mode);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to create source directory %s: %m", mount_entry_source(m));

                        r = label_fix_full(AT_FDCWD, mount_entry_source(m), mount_entry_unprefixed_path(m), /* flags= */ 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set label of the source directory %s: %m", mount_entry_source(m));
                }

                r = chase(mount_entry_source(m), NULL, CHASE_TRAIL_SLASH|CHASE_TRIGGER_AUTOFS, &chased, NULL);
                if (r < 0) {
                        if (m->ignore) {
                                if (r == -ENOENT) {
                                        log_debug_errno(r, "Path '%s' does not exist, ignoring.", mount_entry_source(m));
                                        return 0;
                                }
                                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                                        log_debug_errno(r, "Path '%s' is not accessible, ignoring: %m", mount_entry_source(m));
                                        return 0;
                                }
                        }

                        return log_debug_errno(r, "Failed to follow symlinks on %s: %m", mount_entry_source(m));
                }

                log_debug("Followed source symlinks %s %s %s.",
                          mount_entry_source(m), glyph(GLYPH_ARROW_RIGHT), chased);

                free_and_replace(m->source_malloc, chased);

                what = mount_entry_source(m);
                make = true;
                break;
        }

        case MOUNT_EMPTY_DIR:
        case MOUNT_PRIVATE_TMPFS:
        case MOUNT_TMPFS:
                return mount_tmpfs(m);

        case MOUNT_PRIVATE_TMP:
                what = mount_entry_source(m);
                make = true;
                break;

        case MOUNT_PRIVATE_DEV:
                return mount_private_dev(m, p);

        case MOUNT_BIND_DEV:
                return mount_bind_dev(m);

        case MOUNT_PRIVATE_SYSFS:
                return mount_private_sysfs(m, p);

        case MOUNT_BIND_SYSFS:
                return mount_bind_sysfs(m);

        case MOUNT_PROCFS:
                return mount_procfs(m, p);

        case MOUNT_PRIVATE_CGROUP2FS:
                return mount_private_cgroup2fs(m, p);

        case MOUNT_RUN:
                return mount_run(m);

        case MOUNT_MQUEUEFS:
                return mount_mqueuefs(m);

        case MOUNT_IMAGE:
                return mount_image(m, NULL, p->mount_image_policy, p->runtime_scope);

        case MOUNT_EXTENSION_IMAGE:
                return mount_image(m, root_directory, p->extension_image_policy, p->runtime_scope);

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

                        q = mkdir_parents(mount_entry_path(m), 0755);
                        if (q < 0 && q != -EEXIST)
                                // FIXME: this shouldn't be logged at LOG_WARNING, but be bubbled up, and logged there to avoid duplicate logging
                                log_warning_errno(q, "Failed to create parent directories of destination mount point node '%s', ignoring: %m",
                                                  mount_entry_path(m));
                        else {
                                q = make_mount_point_inode_from_path(what, mount_entry_path(m), 0755);
                                if (q < 0 && q != -EEXIST)
                                        // FIXME: this shouldn't be logged at LOG_WARNING, but be bubbled up, and logged there to avoid duplicate logging
                                        log_warning_errno(q, "Failed to create destination mount point node '%s', ignoring: %m",
                                                          mount_entry_path(m));
                                else
                                        try_again = true;
                        }
                }

                if (try_again)
                        r = mount_nofollow_verbose(LOG_DEBUG, what, mount_entry_path(m), NULL, MS_BIND|(rbind ? MS_REC : 0), NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to mount %s to %s: %m", what, mount_entry_path(m)); // FIXME: this should not be logged here, but be bubbled up, to avoid duplicate logging
        }

        log_debug("Successfully mounted %s to %s", what, mount_entry_path(m));

        /* Take care of id-mapped mounts */
        if (m->idmapped && uid_is_valid(m->idmap_uid) && gid_is_valid(m->idmap_gid)) {
                _cleanup_close_ int userns_fd = -EBADF;
                _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;

                log_debug("Setting an id-mapped mount on %s", mount_entry_path(m));

                /* Do mapping from nobody (in setup_exec_directory()) -> this uid */
                if (strextendf(&uid_map, UID_FMT " " UID_FMT " 1\n", UID_NOBODY, m->idmap_uid) < 0)
                        return log_oom();

                /* Consider StateDirectory=xxx aaa xxx:aaa/222
                 * To allow for later symlink creation (by root) in create_symlinks_from_tuples(), map root as well. */
                if (m->idmap_uid != 0)
                        if (!strextend(&uid_map, "0 0 1\n"))
                                return log_oom();

                if (strextendf(&gid_map, GID_FMT " " GID_FMT " 1\n", GID_NOBODY, m->idmap_gid) < 0)
                        return log_oom();

                if (m->idmap_gid != 0)
                        if (!strextend(&gid_map, "0 0 1\n"))
                                return log_oom();

                userns_fd = userns_acquire(uid_map, gid_map, /* setgroups_deny= */ true);
                if (userns_fd < 0)
                        return log_error_errno(userns_fd, "Failed to allocate user namespace: %m");

                /* Drop SUID, add NOEXEC for the mount to avoid root exploits */
                r = remount_idmap_fd(STRV_MAKE(mount_entry_path(m)), userns_fd, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV);
                if (r < 0)
                        return log_error_errno(r, "Failed to create an id-mapped mount: %m");

                log_debug("ID-mapped mount created successfully for %s from " UID_FMT " to " UID_FMT "", mount_entry_path(m), UID_NOBODY, m->idmap_uid);
        }

        return 1;
}

static bool should_propagate_to_submounts(const MountEntry *m) {
        assert(m);
        return !IN_SET(m->mode, MOUNT_EMPTY_DIR, MOUNT_TMPFS, MOUNT_PRIVATE_TMPFS);
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
        submounts = mount_entry_read_only(m) && should_propagate_to_submounts(m);
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

        submounts = should_propagate_to_submounts(m);
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

        submounts = should_propagate_to_submounts(m);
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
                p->protect_control_groups != PROTECT_CONTROL_GROUPS_NO ||
                p->protect_kernel_tunables ||
                p->protect_proc != PROTECT_PROC_DEFAULT ||
                p->proc_subset != PROC_SUBSET_ALL ||
                p->private_bpf != PRIVATE_BPF_NO ||
                p->private_pids != PRIVATE_PIDS_NO;
}

/* Walk all mount entries and dropping any unused mounts. This affects all
 * mounts:
 * - that are implicitly protected by a path that has been rendered inaccessible
 * - whose immediate parent requests the same protection mode as the mount itself
 * - that are outside of the relevant root directory
 * - which are duplicates
 */
static void sort_and_drop_unused_mounts(MountList *ml, const char *root_directory) {
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

static void mount_entry_path_debug_string(const char *root, MountEntry *m, char **ret_path) {
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

        if (!ret_path)
                return;

        if (!mount_entry_path(m)) {
                *ret_path = NULL;
                return;
        }

        if (root) {
                const char *e = startswith(mount_entry_path(m), root);
                if (e) {
                        *ret_path = strdup(e);
                        return;
                }
        }

        *ret_path = strdup(mount_entry_path(m));
        return;
}

static int apply_mounts(
                MountList *ml,
                const char *root,
                const NamespaceParameters *p,
                char **reterr_path) {

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

                if (reterr_path)
                        *reterr_path = strdup("/proc/self/mountinfo");

                return log_debug_errno(r, "Failed to open %s: %m", "/proc/self/mountinfo");
        }

        /* First round, establish all mounts we need */
        for (;;) {
                bool again = false;

                FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {

                        if (m->state != MOUNT_PENDING)
                                continue;

                        /* ExtensionImages/Directories are first opened in the propagate directory, not in
                         * the root_directory. A private (invisible to the guest) tmpfs instance is mounted
                         * on /run/[user/xyz/]systemd/unit-private-tmp as the storage backend of private
                         * /tmp and /var/tmp. */
                        r = follow_symlink(!IN_SET(m->mode, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY, MOUNT_PRIVATE_TMPFS) ? root : NULL, m);
                        if (r < 0) {
                                mount_entry_path_debug_string(root, m, reterr_path);
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
                                mount_entry_path_debug_string(root, m, reterr_path);
                                return r;
                        }
                        m->state = r == 0 ? MOUNT_SKIPPED : MOUNT_APPLIED;
                }

                if (!again)
                        break;

                sort_and_drop_unused_mounts(ml, root);
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
                        mount_entry_path_debug_string(root, m, reterr_path);
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
                        mount_entry_path_debug_string(root, m, reterr_path);
                        return r;
                }
        }

        /* Fourth round, flip the nosuid bits without a deny list. */
        if (p->mount_nosuid)
                FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {
                        r = make_nosuid(m, proc_self_mountinfo);
                        if (r < 0) {
                                mount_entry_path_debug_string(root, m, reterr_path);
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
                char * const *read_only_paths,
                char * const *inaccessible_paths,
                char * const *empty_directories,
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

        FOREACH_ARRAY(i, temporary_filesystems, n_temporary_filesystems)
                if (path_equal(i->path, "/home"))
                        return true;

        /* If /home is overmounted with some dir from the host it's not writable. */
        FOREACH_ARRAY(i, bind_mounts, n_bind_mounts)
                if (path_equal(i->destination, "/home"))
                        return true;

        return false;
}

static bool namespace_read_only(const NamespaceParameters *p) {
        assert(p);

        return root_read_only(p->read_only_paths,
                              p->protect_system) &&
                home_read_only(p->read_only_paths, p->inaccessible_paths, p->empty_directories,
                               p->bind_mounts, p->n_bind_mounts, p->temporary_filesystems, p->n_temporary_filesystems,
                               p->protect_home) &&
                strv_isempty(p->read_write_paths);
}

int setup_namespace(const NamespaceParameters *p, char **reterr_path) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_strv_free_ char **hierarchies = NULL;
        _cleanup_(mount_list_done) MountList ml = {};
        _cleanup_close_ int userns_fd = -EBADF;
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
                DISSECT_IMAGE_PIN_PARTITION_DEVICES |
                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY |
                DISSECT_IMAGE_VERITY_SHARE;
        MStackFlags mstack_flags = 0;
        int r;

        assert(p);

        /* Make sure that all mknod(), mkdir() calls we do are unaffected by the umask, and the access modes
         * we configure take effect */
        BLOCK_WITH_UMASK(0000);

        bool setup_propagate = !isempty(p->propagate_dir) && !isempty(p->incoming_dir);
        unsigned long mount_propagation_flag = p->mount_propagation_flag != 0 ? p->mount_propagation_flag : MS_SHARED;

        /* Make the whole image read-only if we can determine that we only access it in a read-only fashion. */
        bool ro = namespace_read_only(p);
        if (ro) {
                dissect_image_flags |= DISSECT_IMAGE_READ_ONLY;
                mstack_flags |= MSTACK_RDONLY;
        }

        _cleanup_close_ int _root_mount_fd = -EBADF;
        int root_mount_fd = -EBADF;
        if (pinned_resource_is_set(p->rootfs)) {
                if (p->rootfs->directory_fd >= 0) {

                        /* In "managed" mode we need to map from foreign UID/GID space, hence go via mountfsd */
                        if (p->private_users == PRIVATE_USERS_MANAGED) {
                                userns_fd = namespace_open_by_type(NAMESPACE_USER);
                                if (userns_fd < 0)
                                        return log_debug_errno(userns_fd, "Failed to open our own user namespace: %m");

                                r = mountfsd_mount_directory_fd(
                                                p->mountfsd_link,
                                                p->rootfs->directory_fd,
                                                userns_fd,
                                                dissect_image_flags,
                                                &_root_mount_fd);
                                if (r < 0)
                                        return r;

                                root_mount_fd = _root_mount_fd;
                        }

                        /* Try to to clone the directory mount if we have privs to, so that we can apply the
                         * MS_SLAVE propagation settings right-away. */
                        if (root_mount_fd < 0) {
                                _root_mount_fd = open_tree_attr_with_fallback(
                                                p->rootfs->directory_fd,
                                                "",
                                                OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH|AT_RECURSIVE,
                                                &(struct mount_attr) {
                                                        /* We just remounted / as slave, but that didn't affect the detached
                                                         * mount that we just mounted, so remount that one as slave recursive
                                                         * as well now. */
                                                        .propagation = MS_SLAVE,
                                                });
                                if (_root_mount_fd < 0 && !ERRNO_IS_NEG_PRIVILEGE(_root_mount_fd) && _root_mount_fd != -EINVAL)
                                        return log_debug_errno(_root_mount_fd, "Failed to clone specified directory: %m");

                                root_mount_fd = _root_mount_fd;
                        }
                        /* If we have only a root fd (and we couldn't make it ours), and we have no path,
                         * then try to go on with the literal fd */
                        if (root_mount_fd < 0 && !p->rootfs->directory)
                                root_mount_fd = p->rootfs->directory_fd;
                }

                if (p->rootfs->image_fd >= 0) {
                        SET_FLAG(dissect_image_flags, DISSECT_IMAGE_NO_PARTITION_TABLE, p->verity && p->verity->data_path);

                        if (p->runtime_scope == RUNTIME_SCOPE_SYSTEM) {
                                /* In system mode we mount directly */

                                /* First check if we have a verity device already open and with a fstype pinned by policy. If it
                                 * cannot be found, then fallback to the slow path (full dissect). */
                                r = dissected_image_new_from_existing_verity(
                                                p->rootfs->image,
                                                p->verity,
                                                p->root_image_options,
                                                p->root_image_policy,
                                                /* image_filter= */ NULL,
                                                p->runtime_scope,
                                                dissect_image_flags,
                                                &dissected_image);
                                if (r < 0 && !ERRNO_IS_NEG_DEVICE_ABSENT(r) && r != -ENOPKG)
                                        return r;
                                if (r >= 0)
                                        log_debug("Reusing pre-existing verity-protected root image %s", p->rootfs->image);
                                else {
                                        r = loop_device_make(
                                                        p->rootfs->image_fd,
                                                        FLAGS_SET(dissect_image_flags, DISSECT_IMAGE_DEVICE_READ_ONLY) ? O_RDONLY : -1 /* < 0 means take access mode from fd */,
                                                        /* offset= */ 0,
                                                        /* size= */ UINT64_MAX,
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
                                                        /* image_filter= */ NULL,
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

                                        r = dissected_image_guess_verity_roothash(
                                                        dissected_image,
                                                        p->verity);
                                        if (r < 0)
                                                return r;

                                        r = dissected_image_decrypt(
                                                        dissected_image,
                                                        /* root= */ NULL,
                                                        /* passphrase= */ NULL,
                                                        p->verity,
                                                        p->root_image_policy,
                                                        dissect_image_flags);
                                        if (r < 0)
                                                return log_debug_errno(r, "Failed to decrypt dissected image: %m");
                                }
                        } else {
                                userns_fd = namespace_open_by_type(NAMESPACE_USER);
                                if (userns_fd < 0)
                                        return log_debug_errno(userns_fd, "Failed to open our own user namespace: %m");

                                r = mountfsd_mount_image_fd(
                                                p->mountfsd_link,
                                                p->rootfs->image_fd,
                                                userns_fd,
                                                p->root_image_options,
                                                p->root_image_policy,
                                                p->verity,
                                                dissect_image_flags,
                                                &dissected_image);
                                if (r < 0)
                                        return r;
                        }
                }

                if (p->rootfs->mstack_loaded) {
                        if (p->runtime_scope != RUNTIME_SCOPE_SYSTEM) {
                                userns_fd = namespace_open_by_type(NAMESPACE_USER);
                                if (userns_fd < 0)
                                        return log_debug_errno(userns_fd, "Failed to open our own user namespace: %m");
                        }

                        r = mstack_open_images(
                                        p->rootfs->mstack_loaded,
                                        p->mountfsd_link,
                                        userns_fd,
                                        p->root_image_policy,
                                        /* image_filter= */ NULL,
                                        mstack_flags);
                        if (r < 0)
                                return r;
                }
        }

        if (p->rootfs && p->rootfs->directory)
                root = p->rootfs->directory;
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

        r = append_private_tmp(&ml, p);
        if (r < 0)
                return r;

        r = append_mount_images(&ml, p->mount_images, p->n_mount_images);
        if (r < 0)
                return r;

        r = append_extensions(&ml, root, p->private_namespace_dir, hierarchies, p->extension_images, p->n_extension_images, p->extension_directories);
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

        r = append_protect_control_groups(&ml, p->protect_control_groups, false);
        if (r < 0)
                return r;

        r = append_protect_home(&ml, p->protect_home, p->ignore_protect_paths);
        if (r < 0)
                return r;

        r = append_protect_system(&ml, p->protect_system, false);
        if (r < 0)
                return r;

        r = append_private_bpf(&ml, p->private_bpf, p->protect_kernel_tunables, /* ignore_protect= */ false, p);
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

        /* Only mount /proc/sys/kernel/hostname and domainname read-only if ProtectHostname=yes. Otherwise,
         * ProtectHostname=no allows changing hostname for the host, and ProtectHostname=private allows
         * changing the hostname in the unit's UTS namespace. Note, if proc is mounted with subset=pid then
         * neither of the two paths will exist, i.e. they are implicitly protected by the mount option. */
        if (p->protect_hostname == PROTECT_HOSTNAME_YES) {
                r = append_static_mounts(
                                &ml,
                                protect_hostname_yes_table,
                                ELEMENTSOF(protect_hostname_yes_table),
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
                        .mode = MOUNT_TMPFS,
                        .read_only = true,
                        .options_const = "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST,
                        .flags = MS_NODEV|MS_STRICTATIME|MS_NOSUID|MS_NOEXEC,
                };

                if (p->runtime_scope == RUNTIME_SCOPE_SYSTEM)
                        me->path_const = "/run/credentials";
                else {
                        r = path_extract_directory(p->creds_path, &me->path_malloc);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract parent directory from '%s': %m",
                                                       p->creds_path);
                }

                me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = p->creds_path,
                        .mode = MOUNT_BIND,
                        .read_only = true,
                        .source_const = p->creds_path,
                };
        }

        if (!p->creds_path || p->runtime_scope != RUNTIME_SCOPE_SYSTEM) {
                /* If our service has no credentials store configured, or we're running in user scope, then
                 * make the system credentials tree inaccessible wholesale. */

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

        } else if (p->bind_log_sockets) {
                r = append_bind_mounts(&ml, bind_log_sockets_table, ELEMENTSOF(bind_log_sockets_table));
                if (r < 0)
                        return r;
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

        if (p->notify_socket_path) {
                MountEntry *me = mount_list_extend(&ml);
                if (!me)
                        return log_oom_debug();

                *me = (MountEntry) {
                        .path_const = p->notify_socket_path,
                        .source_const = p->host_notify_socket,
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

        sort_and_drop_unused_mounts(&ml, root);

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

        if (p->n_extension_images > 0 || !strv_isempty(p->extension_directories)) {
                /* ExtensionImages/Directories mountpoint directories will be created while parsing the
                 * mounts to create, so have the parent ready */
                char *extension_dir = strjoina(p->private_namespace_dir, "/unit-extensions");
                (void) mkdir_p(extension_dir, 0600);
        }

        /* Remount / as SLAVE so that nothing now mounted in the namespace
         * shows up in the parent */
        r = mount_nofollow_verbose(LOG_DEBUG, /* what= */ NULL, "/", /* fstype= */ NULL, MS_SLAVE|MS_REC, /* options= */ NULL);
        if (r < 0)
                return r;

        if (root_mount_fd >= 0) {
                /* If we have root_mount_fd we have a ready-to-use detached mount. Attach it. */

                if (move_mount(root_mount_fd, "", AT_FDCWD, root, MOVE_MOUNT_F_EMPTY_PATH) < 0)
                        return log_debug_errno(errno, "Failed to move detached mount to '%s': %m", root);

                r = mount_nofollow_verbose(LOG_DEBUG, /* what= */ NULL, root, /* fstype= */ NULL, MS_SLAVE|MS_REC, /* options= */ NULL);
                if (r < 0)
                        return r;

        } else if (p->rootfs && p->rootfs->directory) {

                /* If we do not have root_mount_fd, but a directory was specified, then we can use it directly. */

                /* A root directory is specified. Turn its directory into bind mount, if it isn't one yet. */
                r = path_is_mount_point_full(root, /* root = */ NULL, AT_SYMLINK_FOLLOW);
                if (r < 0)
                        return log_debug_errno(r, "Failed to detect that %s is a mount point or not: %m", root);
                if (r == 0) {
                        r = mount_nofollow_verbose(LOG_DEBUG, root, root, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL);
                        if (r < 0)
                                return r;
                }

        } else if (dissected_image) {

                /* A root image is specified, mount it to the right place */
                r = dissected_image_mount(
                                dissected_image,
                                root,
                                /* uid_shift= */ UID_INVALID,
                                /* uid_range= */ UID_INVALID,
                                userns_fd,
                                dissect_image_flags);
                if (r < 0)
                        return log_debug_errno(r, "Failed to mount root image: %m");

                /* Now release the block device lock, so that udevd is free to call BLKRRPART on the device
                 * if it likes. */
                if (loop_device) {
                        r = loop_device_flock(loop_device, LOCK_UN);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to release lock on loopback block device: %m");
                }

                r = dissected_image_relinquish(dissected_image);
                if (r < 0)
                        return log_debug_errno(r, "Failed to relinquish dissected image: %m");

        } else if (p->rootfs && p->rootfs->mstack_loaded) {

                r = mstack_make_mounts(p->rootfs->mstack_loaded, root, mstack_flags);
                if (r < 0)
                        return r;

                r = mstack_bind_mounts(p->rootfs->mstack_loaded, root, /* where_fd= */ -EBADF, mstack_flags, /* ret_root_fd= */ NULL);
                if (r < 0)
                        return r;

        } else {
                /* Let's mount the main root directory to the root directory to use */
                r = mount_nofollow_verbose(LOG_DEBUG, "/", root, NULL, MS_BIND|MS_REC, NULL);
                if (r < 0)
                        return r;
        }

        /* Try to set up the new root directory before mounting anything else there. */
        if (pinned_resource_is_set(p->rootfs))
                (void) base_filesystem_create(root, UID_INVALID, GID_INVALID);

        /* Now make the magic happen */
        r = apply_mounts(&ml, root, p, reterr_path);
        if (r < 0)
                return r;

        /* MS_MOVE does not work on MS_SHARED so the remount MS_SHARED will be done later */
        r = mount_switch_root(root, /* mount_propagation_flag = */ 0);
        if (r == -EINVAL && p->rootfs && p->rootfs->directory) {
                /* If we are using root_directory and we don't have privileges (ie: user manager in a user
                 * namespace) and the root_directory is already a mount point in the parent namespace,
                 * MS_MOVE will fail as we don't have permission to change it (with EINVAL rather than
                 * EPERM). Attempt to bind-mount it over itself (like we do above if it's not already a
                 * mount point) and try again. */
                r = mount_nofollow_verbose(LOG_DEBUG, root, root, NULL, MS_BIND|MS_REC, NULL);
                if (r < 0)
                        return r;

                r = mount_switch_root(root, /* mount_propagation_flag= */ 0);
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

        FOREACH_ARRAY(i, b, n) {
                free(i->source);
                free(i->destination);
        }

        free(b);
}

int bind_mount_add(BindMount **b, size_t *n, const BindMount *item) {
        _cleanup_free_ char *s = NULL, *d = NULL;

        assert(b);
        assert(n);
        assert(item);

        s = strdup(item->source);
        if (!s)
                return -ENOMEM;

        d = strdup(item->destination);
        if (!d)
                return -ENOMEM;

        if (!GREEDY_REALLOC(*b, *n + 1))
                return -ENOMEM;

        (*b)[(*n)++] = (BindMount) {
                .source = TAKE_PTR(s),
                .destination = TAKE_PTR(d),
                .read_only = item->read_only,
                .nodev = item->nodev,
                .nosuid = item->nosuid,
                .noexec = item->noexec,
                .recursive = item->recursive,
                .ignore_enoent = item->ignore_enoent,
        };

        return 0;
}

void mount_image_free_many(MountImage *m, size_t n) {
        assert(m || n == 0);

        FOREACH_ARRAY(i, m, n) {
                free(i->source);
                free(i->destination);
                mount_options_free_all(i->mount_options);
        }

        free(m);
}

int mount_image_add(MountImage **m, size_t *n, const MountImage *item) {
        _cleanup_free_ char *s = NULL, *d = NULL;
        _cleanup_(mount_options_free_allp) MountOptions *o = NULL;
        int r;

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

        if (item->mount_options) {
                r = mount_options_dup(item->mount_options, &o);
                if (r < 0)
                        return r;
        }

        if (!GREEDY_REALLOC(*m, *n + 1))
                return -ENOMEM;

        (*m)[(*n)++] = (MountImage) {
                .source = TAKE_PTR(s),
                .destination = TAKE_PTR(d),
                .mount_options = TAKE_PTR(o),
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

        if (!GREEDY_REALLOC(*t, *n + 1))
                return -ENOMEM;

        (*t)[(*n)++] = (TemporaryFileSystem) {
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
        fd = open_mkdir(t, O_EXCL|O_CLOEXEC, 0777);
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

char* namespace_cleanup_tmpdir(char *p) {
        PROTECT_ERRNO;
        if (!streq_ptr(p, RUN_SYSTEMD_EMPTY))
                (void) rmdir(p);
        return mfree(p);
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
        const char *ns_name, *ns_path;
        int r;

        assert(ns_storage_socket);
        assert(ns_storage_socket[0] >= 0);
        assert(ns_storage_socket[1] >= 0);

        ns_name = ASSERT_PTR(namespace_single_flag_to_string(nsflag));

        /* We use the passed socketpair as a storage buffer for our namespace reference fd. Whatever process
         * runs this first shall create a new namespace, all others should just join it. To serialize that we
         * use a file lock on the socket pair.
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

        if (nsflag == CLONE_NEWNET)
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
        NamespaceType type;
        int r;

        assert(ns_storage_socket);
        assert(ns_storage_socket[0] >= 0);
        assert(ns_storage_socket[1] >= 0);
        assert(path);

        /* If the storage socket doesn't contain a ns fd yet, open one via the file system and store it in
         * it. This is supposed to be called ahead of time, i.e. before setup_shareable_ns() which will
         * allocate a new anonymous ns if needed. */

        type = clone_flag_to_namespace_type(nsflag);
        assert(type >= 0);

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

        r = fd_is_namespace(ns, type);
        if (r < 0)
                return r;
        if (r == 0)
                return -EINVAL;

        r = send_one_fd(ns_storage_socket[1], ns, MSG_DONTWAIT);
        if (r < 0)
                return r;

        return 1;
}

static int is_extension_overlay(const char *path, int fd) {
        _cleanup_free_ char *source = NULL;
        _cleanup_close_ int dfd = -EBADF;
        int r;

        assert(path);

        if (fd < 0) {
                r = chase(path, /* root= */ NULL, CHASE_TRAIL_SLASH|CHASE_MUST_BE_DIRECTORY|CHASE_TRIGGER_AUTOFS, /* ret_path= */ NULL, &dfd);
                if (r < 0)
                        return r;
                fd = dfd;
        }

        r = is_mount_point_at(fd, /* path= */ NULL, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether '%s' is a mount point: %m", path);
        if (r == 0)
                return 0;

        r = fd_is_fs_type(fd, OVERLAYFS_SUPER_MAGIC);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if %s is an overlayfs: %m", path);
        if (r == 0)
                return 0;

        /* Check the 'source' field of the mount on mount_path */
        r = path_get_mount_info_at(fd, /* path= */ NULL, /* ret_fstype= */ NULL, /* ret_options= */ NULL, &source);
        if (r < 0)
                return log_debug_errno(r, "Failed to get mount info for %s: %m", path);
        if (!streq_ptr(source, "systemd-extensions"))
                return 0;

        return 1;
}

static int unpeel_get_fd(const char *mount_path, int *ret_fd) {
        _cleanup_close_pair_ int pipe_fds[2] = EBADF_PAIR;
        _cleanup_close_ int fs_fd = -EBADF;
        int r;

        assert(mount_path);
        assert(ret_fd);

        r = socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pipe_fds);
        if (r < 0)
                return log_debug_errno(errno, "Failed to create socket pair: %m");

        /* Clone mount namespace here to unpeel without affecting live process */
        r = pidref_safe_fork("(sd-ns-unpeel)", FORK_DEATHSIG_SIGTERM|FORK_LOG|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE, /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                _cleanup_close_ int dir_fd = -EBADF;

                pipe_fds[0] = safe_close(pipe_fds[0]);

                /* Opportunistically unmount any overlay at this path */
                r = is_extension_overlay(mount_path, /* fd= */ -EBADF);
                if (r < 0) {
                        log_debug_errno(r, "Unable to determine whether '%s' is an extension overlay: %m", mount_path);
                        _exit(EXIT_FAILURE);
                }
                if (r > 0) {
                        r = umount_recursive(mount_path, MNT_DETACH);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                        if (r == 0) /* no umounts done, possible if a previous reload deleted all extensions */
                                log_debug("No overlay layer unmountable from %s", mount_path);
                }

                /* Now that /mount_path is exposed, get an FD for it and pass back */
                dir_fd = open_tree(-EBADF, mount_path, AT_SYMLINK_NOFOLLOW|OPEN_TREE_CLONE);
                if (dir_fd < 0) {
                        log_debug_errno(errno, "Failed to clone mount %s: %m", mount_path);
                        _exit(EXIT_FAILURE);
                }

                r = fd_is_fs_type(dir_fd, OVERLAYFS_SUPER_MAGIC);
                if (r < 0) {
                        log_debug_errno(r, "Unable to determine whether '%s' is an overlay after opening mount tree: %m", mount_path);
                        _exit(EXIT_FAILURE);
                }
                if (r > 0) {
                        log_debug_errno(r, "'%s' is still an overlay after opening mount tree: %m", mount_path);
                        _exit(EXIT_FAILURE);
                }

                r = send_one_fd(pipe_fds[1], dir_fd, 0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to send mount fd: %m");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        pipe_fds[1] = safe_close(pipe_fds[1]);

        r = receive_one_fd(pipe_fds[0], 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to receive mount fd: %m");
        fs_fd = r;

        r = fd_is_fs_type(fs_fd, OVERLAYFS_SUPER_MAGIC);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine if unpeeled directory refers to overlayfs: %m");
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unpeeled mount is still an overlayfs, something is weird, refusing.");

        *ret_fd = TAKE_FD(fs_fd);
        return 0;
}

/* In target namespace, unmounts an existing overlayfs at mount_path (if one exists), grabs FD from the
 * underlying directory, and sets up a new overlayfs mount. Coordinates with parent process over pair_fd:
 * 1. Creates and sends new overlay fs fd to parent
 * 2. Fake-unmounts overlay at mount_path to obtain underlying directory fd to build new overlay
 * 3. Waits for parent to configure layers
 * 4. Performs final mount at mount_path
 *
 * This is used by refresh_extensions_in_namespace() to peel back any existing overlays and reapply them.
 */
static int unpeel_mount_and_setup_overlay(int pair_fd, const char *mount_path) {
        _cleanup_close_ int dir_unpeeled_fd = -EBADF, overlay_fs_fd = -EBADF, mount_fd = -EBADF;
        int r;

        assert(pair_fd >= 0);
        assert(mount_path);

        /* Create new OverlayFS and send to parent */
        overlay_fs_fd = fsopen("overlay", FSOPEN_CLOEXEC);
        if (overlay_fs_fd < 0)
                return log_debug_errno(errno, "Failed to create overlay fs for %s: %m", mount_path);

        r = send_one_fd(pair_fd, overlay_fs_fd, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send overlay fs fd to parent: %m");

        /* Unpeel in cloned mount namespace to get underlying directory fd */
        r = unpeel_get_fd(mount_path, &dir_unpeeled_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to unpeel mount %s: %m", mount_path);

        /* Send the fd to the parent */
        r = send_one_fd(pair_fd, dir_unpeeled_fd, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to send %s fd to parent: %m", mount_path);

        /* Wait for parent to signal overlay configuration completion */
        log_debug("Waiting for configured overlay fs for %s", mount_path);
        r = receive_one_fd(pair_fd, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to receive configured overlay: %m");

        /* Create the mount */
        mount_fd = fsmount(overlay_fs_fd, FSMOUNT_CLOEXEC, /* flags= */ 0);
        if (mount_fd < 0)
                return log_debug_errno(errno, "Failed to create overlay mount: %m");

        /* Move mount to final location */
        r = mount_exchange_graceful(mount_fd, mount_path, /* mount_beneath= */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to move overlay to %s: %m", mount_path);

        return 0;
}

static int refresh_grandchild_proc(
                const PidRef *target,
                MountList *ml,
                const char *overlay_prefix,
                int pidns_fd,
                int mntns_fd,
                int root_fd,
                int pipe_fd) {

        int r;

        assert(pidref_is_set(target));
        assert(ml);
        assert(overlay_prefix);
        assert(pidns_fd >= 0);
        assert(mntns_fd >= 0);
        assert(root_fd >= 0);
        assert(pipe_fd >= 0);

        r = namespace_enter(pidns_fd, mntns_fd, /* netns_fd= */ -EBADF, /* userns_fd= */ -EBADF, root_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to enter namespace: %m");

        /* Handle each overlay mount path */
        FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {
                if (m->mode != MOUNT_OVERLAY)
                        continue;

                /* Need an absolute path under the child namespace, rather than the root's */
                _cleanup_free_ char *mount_path = NULL;
                mount_path = path_join("/",
                                       path_startswith(mount_entry_unprefixed_path(m), overlay_prefix) ?:
                                            mount_entry_unprefixed_path(m));
                if (!mount_path)
                        return log_oom_debug();

                /* If there are no extensions mounted for this overlay layer, instead of setting everything
                 * up, the correct behavior is to unmount the existing overlay in the target namespace to
                 * expose the original files. */
                if (strv_isempty(m->overlay_layers)) {
                        r = is_extension_overlay(mount_path, /* fd= */ -EBADF);
                        if (r < 0)
                                return log_debug_errno(r, "Unable to determine whether '%s' is an extension overlay: %m", mount_path);
                        if (r == 0)
                                continue;

                        log_debug("No extensions for %s, undoing existing mount", mount_path);
                        (void) umount_recursive(mount_path, MNT_DETACH);

                        continue;
                }

                r = unpeel_mount_and_setup_overlay(pipe_fd, mount_path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to setup overlay mount for %s: %m", mount_path);
        }

        return 0;
}

static int handle_mount_from_grandchild(
                MountEntry *m,
                const char *overlay_prefix,
                int **fd_layers,
                size_t *n_fd_layers,
                int pipe_fd) {

        _cleanup_free_ char *layers = NULL, *options = NULL, *hierarchy_path_moved_mount = NULL;
        _cleanup_close_ int hierarchy_path_fd = -EBADF, overlay_fs_fd = -EBADF;
        _cleanup_strv_free_ char **new_layers = NULL;
        int r;

        assert(m);
        assert(overlay_prefix);
        assert(fd_layers);
        assert(n_fd_layers);
        assert(pipe_fd >= 0);

        if (m->mode != MOUNT_OVERLAY)
                return 0;

        const char *mount_path = path_startswith(mount_entry_unprefixed_path(m), overlay_prefix);
        if (!mount_path)
                mount_path = mount_entry_unprefixed_path(m);

        /* If there are no extensions mounted for this overlay layer, we only need to
        * unmount the existing overlay (this is handled in the grandchild process) and
        * would skip the usual cooperative processing here.
        */
        if (strv_isempty(m->overlay_layers)) {
                log_debug("No layers for %s, skip setting up overlay", mount_path);
                return 0;
        }

        /* Receive the fds from grandchild */
        overlay_fs_fd = receive_one_fd(pipe_fd, 0);
        if (overlay_fs_fd < 0)
                return log_debug_errno(overlay_fs_fd, "Failed to receive overlay fs fd from grandchild: %m");

        hierarchy_path_fd = receive_one_fd(pipe_fd, 0);
        if (hierarchy_path_fd < 0)
                return log_debug_errno(hierarchy_path_fd, "Failed to receive fd from grandchild for %s: %m", mount_path);

        /* move_mount so that it is visible on our end. */
        hierarchy_path_moved_mount = path_join(overlay_prefix, mount_path);
        if (!hierarchy_path_moved_mount)
                return log_oom_debug();

        (void) mkdir_p_label(hierarchy_path_moved_mount, 0555);
        r = move_mount(hierarchy_path_fd, "", AT_FDCWD, hierarchy_path_moved_mount, MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_debug_errno(r, "Failed to move mount for %s: %m", mount_path);

        /* Turn all overlay layer directories into FD-based references */
        if (!GREEDY_REALLOC(*fd_layers, *n_fd_layers + strv_length(m->overlay_layers)))
                return log_oom_debug();

        STRV_FOREACH(ol, m->overlay_layers) {
                _cleanup_close_ int tree_fd = -EBADF;

                tree_fd = open_tree(-EBADF, *ol, /* flags= */ 0);
                if (tree_fd < 0)
                        return log_debug_errno(errno, "Failed to open_tree overlay layer '%s': %m", *ol);

                r = strv_extend(&new_layers, FORMAT_PROC_FD_PATH(tree_fd));
                if (r < 0)
                        return log_oom_debug();

                *fd_layers[(*n_fd_layers)++] = TAKE_FD(tree_fd);
        }
        m->overlay_layers = strv_free(m->overlay_layers);
        m->overlay_layers = TAKE_PTR(new_layers);

        layers = strv_join(m->overlay_layers, ":");
        if (!layers)
                return log_oom_debug();

        /* Append the underlying hierarchy path as the last lowerdir */
        options = strjoin(layers, ":", FORMAT_PROC_FD_PATH(hierarchy_path_fd));
        if (!options)
                return log_oom_debug();

        if (fsconfig(overlay_fs_fd, FSCONFIG_SET_STRING, "lowerdir", options, 0) < 0)
                return log_debug_errno(errno, "Failed to set lowerdir=%s: %m", options);

        if (fsconfig(overlay_fs_fd, FSCONFIG_SET_STRING, "source", "systemd-extensions", 0) < 0)
                return log_debug_errno(errno, "Failed to set source=systemd-extensions: %m");

        /* Create the superblock */
        if (fsconfig(overlay_fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
                return log_debug_errno(errno, "Failed to create overlay superblock: %m");

        /* Signal completion to grandchild */
        r = send_one_fd(pipe_fd, overlay_fs_fd, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to signal overlay configuration complete for %s: %m", mount_path);

        return 0;
}

static int refresh_apply_and_prune(const NamespaceParameters *p, MountList *ml) {
        int r;

        assert(p);
        assert(ml);

        /* Open all extensions on the host, drop all sysexts since they won't have /etc/. The list of
         * overlays also need to be updated, so that if it's empty after a confext has been removed, the
         * child process can correctly undo the overlay in the target namespace, rather than attempting to
         * mount an empty overlay which the kernel does not allow, so this pruning has to be done here and
         * not later (nor earlier, as we don't know if an image is a confext until this point). */
        MountEntry *f, *t;
        for (f = ml->mounts, t = ml->mounts; f < ml->mounts + ml->n_mounts; f++) {
                if (IN_SET(f->mode, MOUNT_EXTENSION_DIRECTORY, MOUNT_EXTENSION_IMAGE)) {
                        f->filter_class = IMAGE_CONFEXT;

                        r = apply_one_mount("/", f, p);
                        if (r < 0)
                                return r;
                        /* Nothing happened? Then it is not a confext, prune it from the lists */
                        if (r == 0) {
                                FOREACH_ARRAY(m, ml->mounts, ml->n_mounts) {
                                        if (m->mode != MOUNT_OVERLAY)
                                                continue;

                                        _cleanup_strv_free_ char **pruned = NULL;

                                        STRV_FOREACH(ol, m->overlay_layers)
                                                if (!path_startswith(*ol, mount_entry_path(f))) {
                                                        r = strv_extend(&pruned, *ol);
                                                        if (r < 0)
                                                                return log_oom_debug();
                                                }
                                        strv_free(m->overlay_layers);
                                        m->overlay_layers = TAKE_PTR(pruned);
                                }
                                mount_entry_done(f);
                                continue;
                        }
                }

                *t = *f;
                t++;
        }

        ml->n_mounts = t - ml->mounts;

        return 0;
}

int refresh_extensions_in_namespace(
                const PidRef *target,
                const char *hierarchy_env,
                const NamespaceParameters *p) {

        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF;
        const char *overlay_prefix = "/run/systemd/mount-rootfs";
        _cleanup_(mount_list_done) MountList ml = {};
        _cleanup_free_ char *extension_dir = NULL;
        _cleanup_strv_free_ char **hierarchies = NULL;
        int r;

        assert(pidref_is_set(target));
        assert(hierarchy_env);
        assert(p);

        log_debug("Refreshing extensions in-namespace for hierarchy '%s'", hierarchy_env);

        r = pidref_namespace_open(target, &pidns_fd, &mntns_fd, /* ret_netns_fd= */ NULL, /* ret_userns_fd= */ NULL, &root_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to open namespace: %m");

        r = is_our_namespace(mntns_fd, NAMESPACE_MOUNT);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if target namespace is separate: %m");
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Target namespace is not separate, cannot reload extensions");

        (void) dlopen_cryptsetup();

        extension_dir = path_join(p->private_namespace_dir, "unit-extensions");
        if (!extension_dir)
                return log_oom_debug();

        r = parse_env_extension_hierarchies(&hierarchies, hierarchy_env);
        if (r < 0)
                return r;

        r = append_extensions(
                        &ml,
                        overlay_prefix,
                        p->private_namespace_dir,
                        hierarchies,
                        p->extension_images,
                        p->n_extension_images,
                        p->extension_directories);
        if (r < 0)
                return r;

        sort_and_drop_unused_mounts(&ml, overlay_prefix);
        if (ml.n_mounts == 0)
                return 0;

        /**
         * There are three main steps:
         * 1. In child, set up the extension images and directories in a slave mountns, so that we have
         *    access to their FDs
         * 2. Fork into a grandchild, which will enter the target namespace and attempt to "unpeel" the
         *    overlays to obtain FDs the underlying directories, over which we will reapply the overlays
         * 3. In the child again, receive the FDs and reapply the overlays
         */
        r = pidref_safe_fork(
                        "(sd-ns-refresh-exts)",
                        FORK_DEATHSIG_SIGTERM|FORK_WAIT|FORK_NEW_MOUNTNS|FORK_MOUNTNS_SLAVE,
                        /* ret= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child (host namespace) */
                _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
                _cleanup_(pidref_done_sigkill_wait) PidRef grandchild = PIDREF_NULL;

                 (void) mkdir_p_label(overlay_prefix, 0555);

                r = refresh_apply_and_prune(p, &ml);
                if (r < 0) {
                        log_debug_errno(r, "Failed to apply extensions for refreshing: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Create a grandchild process to handle the unmounting and reopening of hierarchy */
                r = socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pair);
                if (r < 0) {
                        log_debug_errno(errno, "Failed to create socket pair: %m");
                        _exit(EXIT_FAILURE);
                }

                r = pidref_safe_fork("(sd-ns-refresh-exts-grandchild)", FORK_LOG|FORK_DEATHSIG_SIGKILL, &grandchild);
                if (r < 0)
                        _exit(EXIT_FAILURE);
                if (r == 0) {
                        /* Grandchild (target service namespace) */
                        pair[0] = safe_close(pair[0]);

                        r = refresh_grandchild_proc(target, &ml, overlay_prefix, pidns_fd, mntns_fd, root_fd, pair[1]);
                        if (r < 0) {
                                pair[1] = safe_close(pair[1]);
                                _exit(EXIT_FAILURE);
                        }

                        _exit(EXIT_SUCCESS);
                }

                pair[1] = safe_close(pair[1]);

                /* Until kernel 6.15, the FDs to the individual layers used to set up the OverlayFS via
                 * lowerdir=/proc/self/fd/X need to remain open until the OverlayFS mount is _attached_
                 * (as opposed to merely created) to its mount point, hence we need to ensure these FDs
                 * stay open until the grandchild has attached the mount and exited. */
                // TODO: once the kernel baseline is >= 6.15, move the FD array into the helper function
                // and close them immediately
                int *fd_layers = NULL;
                size_t n_fd_layers = 0;
                CLEANUP_ARRAY(fd_layers, n_fd_layers, close_many_and_free);

                FOREACH_ARRAY(m, ml.mounts, ml.n_mounts) {
                        r = handle_mount_from_grandchild(m, overlay_prefix, &fd_layers, &n_fd_layers, pair[0]);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                r = pidref_wait_for_terminate_and_check("(sd-ns-refresh-exts-grandchild)", &grandchild, 0);
                if (r < 0) {
                        log_debug_errno(r, "Failed to wait for target namespace process to finish: %m");
                        _exit(EXIT_FAILURE);
                }

                pidref_done(&grandchild);

                if (r != EXIT_SUCCESS) {
                        log_debug("Target namespace fork did not succeed");
                        _exit(EXIT_FAILURE);
                }

                _exit(EXIT_SUCCESS);
        }

        return 0;
}

static const char *const protect_home_table[_PROTECT_HOME_MAX] = {
        [PROTECT_HOME_NO]        = "no",
        [PROTECT_HOME_YES]       = "yes",
        [PROTECT_HOME_READ_ONLY] = "read-only",
        [PROTECT_HOME_TMPFS]     = "tmpfs",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_home, ProtectHome, PROTECT_HOME_YES);

static const char *const protect_hostname_table[_PROTECT_HOSTNAME_MAX] = {
        [PROTECT_HOSTNAME_NO]      = "no",
        [PROTECT_HOSTNAME_YES]     = "yes",
        [PROTECT_HOSTNAME_PRIVATE] = "private",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_hostname, ProtectHostname, PROTECT_HOSTNAME_YES);

static const char *const protect_system_table[_PROTECT_SYSTEM_MAX] = {
        [PROTECT_SYSTEM_NO]     = "no",
        [PROTECT_SYSTEM_YES]    = "yes",
        [PROTECT_SYSTEM_FULL]   = "full",
        [PROTECT_SYSTEM_STRICT] = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_system, ProtectSystem, PROTECT_SYSTEM_YES);

static const char *const protect_control_groups_table[_PROTECT_CONTROL_GROUPS_MAX] = {
        [PROTECT_CONTROL_GROUPS_NO]      = "no",
        [PROTECT_CONTROL_GROUPS_YES]     = "yes",
        [PROTECT_CONTROL_GROUPS_PRIVATE] = "private",
        [PROTECT_CONTROL_GROUPS_STRICT]  = "strict",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(protect_control_groups, ProtectControlGroups, PROTECT_CONTROL_GROUPS_YES);

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

static const char* const private_bpf_table[_PRIVATE_BPF_MAX] = {
        [PRIVATE_BPF_NO]  = "no",
        [PRIVATE_BPF_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(private_bpf, PrivateBPF, PRIVATE_BPF_YES);

#include "bpf-delegate-configs.inc"

DEFINE_STRING_TABLE_LOOKUP(bpf_delegate_cmd, uint64_t);
DEFINE_STRING_TABLE_LOOKUP(bpf_delegate_map_type, uint64_t);
DEFINE_STRING_TABLE_LOOKUP(bpf_delegate_prog_type, uint64_t);
DEFINE_STRING_TABLE_LOOKUP(bpf_delegate_attach_type, uint64_t);

char* bpf_delegate_to_string(uint64_t u, const char * (*parser)(uint64_t) _const_ ) {
        assert(parser);

        if (u == UINT64_MAX)
                return strdup("any");

        _cleanup_free_ char *buf = NULL;

        BIT_FOREACH(i, u) {
                const char *s = parser(i);
                if (s) {
                        if (!strextend_with_separator(&buf, ",", s))
                                return NULL;
                } else {
                        if (strextendf_with_separator(&buf, ",", "%d", i) < 0)
                                return NULL;
                }
        }

        return TAKE_PTR(buf) ?: strdup("");
}

int bpf_delegate_from_string(const char *s, uint64_t *ret, uint64_t (*parser)(const char *)) {
        int r;

        assert(s);
        assert(ret);
        assert(parser);

        if (streq(s, "any")) {
                *ret = UINT64_MAX;
                return 0;
        }

        uint64_t mask = 0;
        for (;;) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&s, &word, ",", /* flags= */ 0);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse delegate options \"%s\": %m", s);
                if (r == 0)
                        break;

                r = parser(word);
                if (r < 0)
                        log_warning_errno(r, "Unknown BPF delegate option, ignoring: %s", word);
                else
                        mask |= UINT64_C(1) << r;
        }

        *ret = mask;

        return 0;
}

static const char* const private_tmp_table[_PRIVATE_TMP_MAX] = {
        [PRIVATE_TMP_NO]           = "no",
        [PRIVATE_TMP_CONNECTED]    = "connected",
        [PRIVATE_TMP_DISCONNECTED] = "disconnected",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(private_tmp, PrivateTmp, PRIVATE_TMP_CONNECTED);

static const char* const private_users_table[_PRIVATE_USERS_MAX] = {
        [PRIVATE_USERS_NO]       = "no",
        [PRIVATE_USERS_SELF]     = "self",
        [PRIVATE_USERS_IDENTITY] = "identity",
        [PRIVATE_USERS_FULL]     = "full",
        [PRIVATE_USERS_MANAGED]  = "managed",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(private_users, PrivateUsers, PRIVATE_USERS_SELF);

static const char* const private_pids_table[_PRIVATE_PIDS_MAX] = {
        [PRIVATE_PIDS_NO]  = "no",
        [PRIVATE_PIDS_YES] = "yes",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(private_pids, PrivatePIDs, PRIVATE_PIDS_YES);

void pinned_resource_done(PinnedResource *p) {
        assert(p);

        p->directory_fd = safe_close(p->directory_fd);
        p->directory = mfree(p->directory);
        p->image_fd = safe_close(p->image_fd);
        p->image = mfree(p->image);
        p->mstack_loaded = mstack_free(p->mstack_loaded);
        p->mstack = mfree(p->mstack);
}

bool pinned_resource_is_set(const PinnedResource *p) {
        if (!p)
                return false;

        return p->directory_fd >= 0 ||
                p->directory ||
                p->image_fd >= 0 ||
                p->image ||
                p->mstack_loaded ||
                p->mstack;
}
