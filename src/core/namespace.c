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
#include "copy.h"
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
#include "mkdir.h"
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
#include "set.h"
#include "siphash24.h"
#include "socket-util.h"
#include "stat-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "vpick.h"

#define DEV_MOUNT_OPTIONS (MS_NOSUID|MS_STRICTATIME|MS_NOEXEC)

/* Fixed mount point that units overmount with a private tmpfs when they need a staging area for
 * mounts that shall stay private to their mount namespace, e.g. the extension images. */
#define UNIT_STAGING_DIR "/run/systemd/staging"

/* The directory the mount namespace is assembled in, before it is switched to /. Created by PID 1
 * early on, like /run/systemd/staging. */
#define STAGING_ROOT_DIR "/run/systemd/mount-rootfs"

typedef enum MountKind {
        /* This is ordered by priority: when multiple entries have the same path, the lower one
         * wins. MOUNT_ADJUST mounts nothing on its own and only toggles the entry flags, hence
         * it sorts after all the mounts: when it loses against a mount on the same path, its
         * attributes are merged into the winning entry, see drop_duplicates(). The extension
         * kinds are set up outside of the root directory and never share their path with other
         * entries, hence they are placed at the bottom. */
        MOUNT_INACCESSIBLE,
        MOUNT_OVERLAY,
        MOUNT_IMAGE,
        MOUNT_BIND,
        MOUNT_BIND_RECURSIVE,
        MOUNT_TMPFS,
        MOUNT_PRIVATE_TMP,
        MOUNT_PRIVATE_DEV,
        MOUNT_BIND_DEV,
        MOUNT_PRIVATE_SYSFS,
        MOUNT_BIND_SYSFS,
        MOUNT_PROCFS,
        MOUNT_CGROUP2FS,
        MOUNT_MQUEUEFS,
        MOUNT_BPFFS,               /* Mounted with fsmount() and move_mount() */
        MOUNT_ADJUST,
        MOUNT_EXTENSION_DIRECTORY, /* Bind-mounted outside the root, used by later mounts */
        MOUNT_EXTENSION_IMAGE,     /* Mounted outside the root, used by later mounts */
        _MOUNT_KIND_MAX,
        _MOUNT_KIND_INVALID = -EINVAL,
} MountKind;

typedef enum MountEntryFlags {
        /* The attributes: merged into the surviving entry by drop_duplicates(); if they
         * conflict, the more restrictive one wins. */
        MOUNT_RDONLY             = 1 << 0, /* Set MS_RDONLY on the mount itself */
        MOUNT_WRONLY             = 1 << 1, /* Clear MS_RDONLY, a carve-out from a stricter setting */
        MOUNT_NOEXEC             = 1 << 2, /* Set MS_NOEXEC on the mount itself */
        MOUNT_EXEC               = 1 << 3, /* Clear MS_NOEXEC on the mount itself */
        MOUNT_NOSUID             = 1 << 4, /* Set MS_NOSUID on the mount itself */
        _MOUNT_ATTR_MASK         = MOUNT_RDONLY|MOUNT_WRONLY|MOUNT_NOEXEC|MOUNT_EXEC|MOUNT_NOSUID,

        /* MOUNT_IMPLICIT is set for the entries implied by the sandboxing options rather than
         * explicitly configured, which lose against the explicitly configured ones on the same
         * path. */
        MOUNT_IMPLICIT           = 1 << 5, /* Implied by a sandboxing option, not explicitly configured */
        MOUNT_IGNORE             = 1 << 6, /* Ignore if the path does not exist */
} MountEntryFlags;

typedef enum MountEntryState {
        MOUNT_PENDING,
        MOUNT_APPLIED,
        MOUNT_SKIPPED,
        _MOUNT_ENTRY_STATE_MAX,
        _MOUNT_ENTRY_STATE_INVALID = -EINVAL,
} MountEntryState;

typedef struct MountEntry {
        char *path;                /* Mount point, prefixed with the staging root directory, unless the entry is set up outside of it */
        MountKind kind;
        MountEntryFlags flags;     /* Semantics of the entry, see MountEntryFlags */
        MountEntryState state;     /* Whether it was already processed or skipped */
        char *source;              /* The source path, for bind mounts or images */
        char *options;             /* Mount options for tmpfs */
        unsigned long mount_flags; /* Mount flags for TMPFS; use MOUNT_RDONLY in the flags for MS_RDONLY */
        unsigned n_followed;
        const MountOptions *image_mount_options;
        char **overlay_layers;
        VeritySettings verity;
        ImageClass filter_class;   /* Used for live updates to skip inapplicable images */
        bool idmapped;
        uid_t idmap_uid;
        gid_t idmap_gid;
} MountEntry;

static const BindMount bind_log_sockets_table[] = {
        { (char*) "/run/systemd/journal/socket",  (char*) "/run/systemd/journal/socket",  .read_only = true, .nosuid = true, .noexec = true, .nodev = true, .ignore_enoent = true },
        { (char*) "/run/systemd/journal/stdout",  (char*) "/run/systemd/journal/stdout",  .read_only = true, .nosuid = true, .noexec = true, .nodev = true, .ignore_enoent = true },
        { (char*) "/run/systemd/journal/dev-log", (char*) "/run/systemd/journal/dev-log", .read_only = true, .nosuid = true, .noexec = true, .nodev = true, .ignore_enoent = true },
};

/* If MountAPIVFS= is used, let's mount /proc/, /dev/ and /sys/, but only as a fallback if the user hasn't
 * mounted something already. These mounts are hence overridden by any other explicitly configured mounts. */
static const MountEntry apivfs_table[] = {
        { (char*) "/proc",               MOUNT_PROCFS,       MOUNT_NOEXEC                           },
        { (char*) "/dev",                MOUNT_BIND_DEV                                             },
        { (char*) "/sys",                MOUNT_BIND_SYSFS,   MOUNT_NOEXEC                           },
};

/* The writable /run/ tmpfs of MountAPIVFS=. Only set up when a separate root directory is used: there /run/
 * is a private tmpfs that must be writable (e.g. for /run/host/). Without a separate root directory /run/ is
 * the host's, and left out here so that it stays subject to the read-only remount of ProtectSystem=strict
 * (and does not leak as writable). A fresh tmpfs is always mounted here, so that even a /run/ already present
 * in the root tree (e.g. the host's bind-mounted in) is replaced by a private one. */
static const MountEntry apivfs_run_table[] = {
        { (char*) "/run",                MOUNT_TMPFS,
          .options = (char*) "mode=0755" TMPFS_LIMITS_RUN, .mount_flags = MS_NOSUID|MS_NODEV|MS_STRICTATIME },
};

/* ProtectKernelTunables= option and the related filesystem APIs */
static const MountEntry protect_kernel_tunables_proc_table[] = {
        { (char*) "/proc/acpi",          MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/apm",           MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              }, /* Obsolete API, there's no point in permitting access to this, ever */
        { (char*) "/proc/asound",        MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/bus",           MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/fs",            MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/irq",           MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/kallsyms",      MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
        { (char*) "/proc/kcore",         MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
        { (char*) "/proc/latency_stats", MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/mtrr",          MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/scsi",          MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/sys",           MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/sysrq-trigger", MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/proc/timer_stats",   MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
};

static const MountEntry protect_kernel_tunables_sys_table[] = {
        { (char*) "/sys",                MOUNT_ADJUST,       MOUNT_RDONLY                           },
        { (char*) "/sys/fs/cgroup",      MOUNT_ADJUST,       MOUNT_WRONLY                           }, /* read-only comes from ProtectControlGroups= */
        { (char*) "/sys/fs/selinux",     MOUNT_ADJUST,       MOUNT_WRONLY|MOUNT_IGNORE              },
        { (char*) "/sys/kernel/debug",   MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/sys/kernel/tracing", MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
};

/* PrivateBPF= option */
static const MountEntry private_bpf_no_table[] = {
        { (char*) "/sys/fs/bpf",         MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
};

/* ProtectKernelModules= option */
static const MountEntry protect_kernel_modules_table[] = {
        { (char*) "/usr/lib/modules",    MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
};

/* ProtectKernelLogs= option */
static const MountEntry protect_kernel_logs_proc_table[] = {
        { (char*) "/proc/kmsg",          MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
};

static const MountEntry protect_kernel_logs_dev_table[] = {
        { (char*) "/dev/kmsg",           MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
};

/*
 * ProtectHome=read-only. Protect $HOME and $XDG_RUNTIME_DIR and rest of
 * system should be protected by ProtectSystem=.
 */
static const MountEntry protect_home_read_only_table[] = {
        { (char*) "/home",               MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/run/user",           MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/root",               MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
};

/* ProtectHome=tmpfs */
static const MountEntry protect_home_tmpfs_table[] = {
        { (char*) "/home",               MOUNT_TMPFS,        MOUNT_RDONLY|MOUNT_IGNORE,
          .options = (char*) "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST, .mount_flags = MS_NODEV|MS_STRICTATIME },
        { (char*) "/run/user",           MOUNT_TMPFS,        MOUNT_RDONLY|MOUNT_IGNORE,
          .options = (char*) "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST, .mount_flags = MS_NODEV|MS_STRICTATIME },
        { (char*) "/root",               MOUNT_TMPFS,        MOUNT_RDONLY|MOUNT_IGNORE,
          .options = (char*) "mode=0700" TMPFS_LIMITS_EMPTY_OR_ALMOST, .mount_flags = MS_NODEV|MS_STRICTATIME },
};

/* ProtectHome=yes */
static const MountEntry protect_home_yes_table[] = {
        { (char*) "/home",               MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
        { (char*) "/run/user",           MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
        { (char*) "/root",               MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE },
};

/* ProtectControlGroups=yes */
static const MountEntry protect_control_groups_yes_table[] = {
        { (char*) "/sys/fs/cgroup",      MOUNT_ADJUST,       MOUNT_RDONLY                           },
};

/* ProtectControlGroups=private. Note mount_private_apivfs() always use MS_NOSUID|MS_NOEXEC|MS_NODEV so
 * flags are not set here. */
static const MountEntry protect_control_groups_private_table[] = {
        { (char*) "/sys/fs/cgroup",      MOUNT_CGROUP2FS,    MOUNT_NOEXEC                           },
};

/* ProtectControlGroups=strict */
static const MountEntry protect_control_groups_strict_table[] = {
        { (char*) "/sys/fs/cgroup",      MOUNT_CGROUP2FS,    MOUNT_RDONLY|MOUNT_NOEXEC              },
};

/* ProtectSystem=yes */
static const MountEntry protect_system_yes_table[] = {
        { (char*) "/usr",                MOUNT_ADJUST,       MOUNT_RDONLY                           },
        { (char*) "/boot",               MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/efi",                MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
};

/* ProtectSystem=full includes ProtectSystem=yes */
static const MountEntry protect_system_full_table[] = {
        { (char*) "/usr",                MOUNT_ADJUST,       MOUNT_RDONLY                           },
        { (char*) "/boot",               MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/efi",                MOUNT_ADJUST,       MOUNT_RDONLY|MOUNT_IGNORE              },
        { (char*) "/etc",                MOUNT_ADJUST,       MOUNT_RDONLY                           },
};

/* ProtectSystem=strict. In this strict mode, we mount everything read-only, except for /proc, /dev, and
 * /sys which are the kernel API VFS and left writable. PrivateDevices= + ProtectKernelTunables=
 * protect those, and these options should be fully orthogonal. (And of course /home and friends are also
 * left writable, as ProtectHome= shall manage those, orthogonally).
 */
static const MountEntry protect_system_strict_table[] = {
        { (char*) "/",                   MOUNT_ADJUST,       MOUNT_RDONLY                           },
        { (char*) "/proc",               MOUNT_ADJUST,       MOUNT_WRONLY                           }, /* ProtectKernelTunables= */
        { (char*) "/sys",                MOUNT_ADJUST,       MOUNT_WRONLY                           }, /* ProtectKernelTunables= */
        { (char*) "/dev",                MOUNT_ADJUST,       MOUNT_WRONLY                           }, /* PrivateDevices= */
        { (char*) "/home",               MOUNT_ADJUST,       MOUNT_WRONLY|MOUNT_IGNORE              }, /* ProtectHome= */
        { (char*) "/run/user",           MOUNT_ADJUST,       MOUNT_WRONLY|MOUNT_IGNORE              }, /* ProtectHome= */
        { (char*) "/root",               MOUNT_ADJUST,       MOUNT_WRONLY|MOUNT_IGNORE              }, /* ProtectHome= */
};

/* ProtectHostname=yes */
static const MountEntry protect_hostname_yes_table[] = {
        { (char*) "/proc/sys/kernel/hostname",   MOUNT_ADJUST, MOUNT_RDONLY },
        { (char*) "/proc/sys/kernel/domainname", MOUNT_ADJUST, MOUNT_RDONLY },
};

static const char * const kind_table[_MOUNT_KIND_MAX] = {
        [MOUNT_INACCESSIBLE]        = "inaccessible",
        [MOUNT_OVERLAY]             = "overlay",
        [MOUNT_IMAGE]               = "image",
        [MOUNT_BIND]                = "bind",
        [MOUNT_BIND_RECURSIVE]      = "bind-recursive",
        [MOUNT_TMPFS]               = "tmpfs",
        [MOUNT_PRIVATE_TMP]         = "private-tmp",
        [MOUNT_PRIVATE_DEV]         = "private-dev",
        [MOUNT_BIND_DEV]            = "bind-dev",
        [MOUNT_PRIVATE_SYSFS]       = "private-sysfs",
        [MOUNT_BIND_SYSFS]          = "bind-sysfs",
        [MOUNT_PROCFS]              = "procfs",
        [MOUNT_CGROUP2FS]           = "cgroup2fs",
        [MOUNT_MQUEUEFS]            = "mqueuefs",
        [MOUNT_BPFFS]               = "bpf",
        [MOUNT_ADJUST]              = "adjust",
        [MOUNT_EXTENSION_DIRECTORY] = "extension-directory",
        [MOUNT_EXTENSION_IMAGE]     = "extension-image",
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

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(kind, MountKind);

static MountEntry* mount_entry_free(MountEntry *e) {
        if (!e)
                return NULL;

        e->path = mfree(e->path);
        e->source = mfree(e->source);
        e->options = mfree(e->options);
        e->overlay_layers = strv_free(e->overlay_layers);
        verity_settings_done(&e->verity);
        return mfree(e);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(MountEntry*, mount_entry_free);

static const char* mount_entry_root_dir(const MountEntry *e) {
        assert(e);

        /* The extensions are set up outside of the root directory, in the unit's private
         * staging area below /run/systemd/staging. */
        return IN_SET(e->kind, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY) ? UNIT_STAGING_DIR : STAGING_ROOT_DIR;
}

static void mount_entry_hash_func(const MountEntry *e, struct siphash *state) {
        assert(e);

        siphash24_compress_boolean(IN_SET(e->kind, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY), state);
        path_hash_func(e->path, state);
}

static int mount_entry_compare_func(const MountEntry *a, const MountEntry *b) {
        int r;

        assert(a);
        assert(b);

        /* Extension images and directories are used by later mounts as a base, so they sort
         * first regardless of the prefix - they are set up outside of the root anyway. */
        r = -CMP(IN_SET(a->kind, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY),
                 IN_SET(b->kind, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY));
        if (r != 0)
                return r;

        /* If the paths are not equal, then order prefixes first */
        return path_compare(a->path, b->path);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                mount_entry_hash_ops,
                MountEntry, mount_entry_hash_func, mount_entry_compare_func,
                MountEntry, mount_entry_free);

static int mount_entry_priority_compare(const MountEntry *a, const MountEntry *b) {
        int r;

        assert(a);
        assert(b);

        /* Attribute-only entries lose against the mounts, so that their attributes are merged
         * into the winning mount entry. */
        r = CMP(a->kind == MOUNT_ADJUST, b->kind == MOUNT_ADJUST);
        if (r != 0)
                return r;

        /* Explicitly configured entries override the implied ones. */
        r = CMP(FLAGS_SET(a->flags, MOUNT_IMPLICIT), FLAGS_SET(b->flags, MOUNT_IMPLICIT));
        if (r != 0)
                return r;

        /* Then the kinds by priority. */
        r = CMP(a->kind, b->kind);
        if (r != 0)
                return r;

        /* Finally the attributes, where the more restrictive ones sort first. */
        return CMP(a->flags & _MOUNT_ATTR_MASK, b->flags & _MOUNT_ATTR_MASK);
}

static void mount_entry_merge_attributes(MountEntry *to, const MountEntry *from) {
        MountEntryFlags attrs;

        assert(to);
        assert(from);

        /* An explicitly configured mount owns its attributes: the attributes of the entries
         * implied by the sandboxing options are defaults for the case they win themselves,
         * and shall not tighten a mount the user configured for the same path, as the
         * explicitly configured mounts carry their own attributes, e.g. the "ro" option of
         * TemporaryFileSystem=. Explicitly configured attributes still apply, and the
         * implied entries keep taking attributes, so that e.g. ReadOnlyPaths= tightens the
         * tmpfs implied by ProtectHome=tmpfs. */
        if (to->kind != MOUNT_ADJUST &&
            !FLAGS_SET(to->flags, MOUNT_IMPLICIT) &&
            FLAGS_SET(from->flags, MOUNT_IMPLICIT)) {
                if ((from->flags & _MOUNT_ATTR_MASK) != 0)
                        log_debug("Ignoring attributes of the implied %s entry at %s, the explicitly configured %s entry does not accept them.",
                                  kind_to_string(from->kind), from->path, kind_to_string(to->kind));
                return;
        }

        attrs = (to->flags | from->flags) & _MOUNT_ATTR_MASK;

        /* If the attributes conflict, the more restrictive one wins. */
        if (attrs & MOUNT_RDONLY)
                attrs &= ~MOUNT_WRONLY;
        if (attrs & MOUNT_NOEXEC)
                attrs &= ~MOUNT_EXEC;

        to->flags = (to->flags & ~_MOUNT_ATTR_MASK) | attrs;
}

static MountEntry* mount_entry_dup(const MountEntry *e) {
        _cleanup_(mount_entry_freep) MountEntry *copy = NULL;
        int r;

        assert(e);

        /* Duplicates the entry, prefixing its path with the root directory appropriate for
         * its kind, and duplicating its strings. Hence, the caller may pass a stack or
         * compound literal entry, with an unprefixed path and borrowed strings. */

        copy = newdup(MountEntry, e, 1);
        if (!copy)
                return NULL;

        /* The strings are replaced with copies below; neutralize them first, so that the copy
         * is safe to free on error. */
        copy->path = NULL;
        copy->source = NULL;
        copy->options = NULL;
        copy->overlay_layers = NULL;
        copy->verity = VERITY_SETTINGS_DEFAULT;

        copy->path = path_join(mount_entry_root_dir(e), e->path);
        if (!copy->path)
                return NULL;

        r = strdup_to(&copy->source, e->source);
        if (r < 0)
                return NULL;

        r = strdup_to(&copy->options, e->options);
        if (r < 0)
                return NULL;

        if (e->overlay_layers) {
                copy->overlay_layers = strv_copy(e->overlay_layers);
                if (!copy->overlay_layers)
                        return NULL;
        }

        r = verity_settings_copy(&copy->verity, &e->verity);
        if (r < 0)
                return NULL;

        return TAKE_PTR(copy);
}

static int mount_append_entry_consume(Set **s, MountEntry *entry_consumed) {
        _cleanup_(mount_entry_freep) MountEntry *e = ASSERT_PTR(entry_consumed);

        assert(s);

        /* Registers an owned entry in the path-keyed set. The path must be the final one
         * already, i.e. prefixed with the root directory appropriate for its kind. If an
         * entry for the same path exists already, the one with the higher priority wins and
         * takes over the attributes of the other one. Note that the entry is always
         * consumed. */

        MountEntry *existing = set_get(*s, e);
        if (!existing)
                return set_ensure_consume(s, &mount_entry_hash_ops, TAKE_PTR(e));

        log_debug("%s (%s%s) is duplicate.",
                  e->path,
                  FLAGS_SET(e->flags, MOUNT_IMPLICIT) ? "implicit " : "",
                  kind_to_string(e->kind));

        if (mount_entry_priority_compare(e, existing) < 0) {
                /* The new entry wins: replace the existing one. */
                mount_entry_merge_attributes(e, existing);

                set_remove(*s, existing);
                mount_entry_free(existing);

                return set_ensure_consume(s, &mount_entry_hash_ops, TAKE_PTR(e));
        }

        mount_entry_merge_attributes(existing, e);

        return 0;
}

static int mount_append_entry(Set **s, const MountEntry *e) {
        _cleanup_(mount_entry_freep) MountEntry *copy = NULL;

        assert(s);
        assert(e);

        copy = mount_entry_dup(e);
        if (!copy)
                return -ENOMEM;

        return mount_append_entry_consume(s, TAKE_PTR(copy));
}

static int append_access_mounts(Set **s, const AccessMount *access_mounts, size_t n) {
        static const struct {
                MountKind kind;
                MountEntryFlags flags;
        } table[_ACCESS_MOUNT_MAX] = {
                [ACCESS_MOUNT_READ_WRITE]   = { MOUNT_ADJUST,       MOUNT_WRONLY              },
                [ACCESS_MOUNT_READ_ONLY]    = { MOUNT_ADJUST,       MOUNT_RDONLY              },
                [ACCESS_MOUNT_INACCESSIBLE] = { MOUNT_INACCESSIBLE, MOUNT_RDONLY|MOUNT_NOEXEC },
                [ACCESS_MOUNT_EXEC]         = { MOUNT_ADJUST,       MOUNT_EXEC                },
                [ACCESS_MOUNT_NOEXEC]       = { MOUNT_ADJUST,       MOUNT_NOEXEC              },
        };

        int r;

        assert(s);

        /* Adds the compiled user-supplied READ_WRITE/READ_ONLY/INACCESSIBLE/EXEC/NOEXEC entries */

        FOREACH_ARRAY(a, access_mounts, n) {
                r = mount_append_entry(s, &(MountEntry) {
                                .path = a->path,
                                .kind = table[a->mode].kind,
                                .flags = table[a->mode].flags | (a->ignore ? MOUNT_IGNORE : 0),
                        });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_empty_dir_mounts(Set **s, char **strv) {
        int r;

        assert(s);

        /* Adds tmpfs mounts to provide readable but empty directories. This is primarily used to implement the
         * "/private/" boundary directories for DynamicUser=1. */

        STRV_FOREACH(i, strv) {
                r = mount_append_entry(s, &(MountEntry) {
                                .path = *i,
                                .kind = MOUNT_TMPFS,
                                .flags = MOUNT_RDONLY|MOUNT_IMPLICIT,
                                .options = (char*) "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST,
                                .mount_flags = MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
                        });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_bind_mounts(Set **s, const BindMount *binds, size_t n, bool implicit) {
        int r;

        assert(s);
        assert(binds || n == 0);

        FOREACH_ARRAY(b, binds, n) {
                r = mount_append_entry(s, &(MountEntry) {
                                .path = b->destination,
                                .kind = b->recursive ? MOUNT_BIND_RECURSIVE : MOUNT_BIND,
                                .flags = (implicit ? MOUNT_IMPLICIT : 0) |
                                         (b->read_only ? MOUNT_RDONLY : 0) |
                                         (b->noexec ? MOUNT_NOEXEC : 0) |
                                         (b->nosuid ? MOUNT_NOSUID : 0) |
                                         (b->ignore_enoent ? MOUNT_IGNORE : 0),
                                .mount_flags = b->nodev ? MS_NODEV : 0,
                                .source = b->source,
                                .idmapped = b->idmapped,
                                .idmap_uid = b->uid,
                                .idmap_gid = b->gid,
                        });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_mount_images(Set **s, const MountImage *mount_images, size_t n) {
        int r;

        assert(s);
        assert(mount_images || n == 0);

        FOREACH_ARRAY(m, mount_images, n) {
                _cleanup_(verity_settings_done) VeritySettings verity = VERITY_SETTINGS_DEFAULT;

                r = verity_settings_load(&verity, m->source, /* root_hash_path= */ NULL, /* root_hash_sig_path= */ NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to check verity root hash of %s: %m", m->source);

                r = mount_append_entry(s, &(MountEntry) {
                                .path = m->destination,
                                .kind = MOUNT_IMAGE,
                                .source = m->source,
                                .image_mount_options = m->mount_options,
                                .flags = m->ignore_enoent ? MOUNT_IGNORE : 0,
                                .verity = verity,
                                .filter_class = _IMAGE_CLASS_INVALID,
                        });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_extensions(
                Set **s,
                char **hierarchies,
                const MountImage *mount_images,
                size_t n_mount_images,
                char **extension_directories) {

        char ***overlays = NULL;
        size_t n_overlays = 0;
        int r;

        assert(s);

        if (n_mount_images == 0 && strv_isempty(extension_directories))
                return 0;

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

                r = path_pick(/* root_path= */ NULL,
                              /* root_fd= */ AT_FDCWD,
                              /* dir_fd= */ AT_FDCWD,
                              m->source,
                              pick_filter_image_raw,
                              ELEMENTSOF(pick_filter_image_raw),
                              /* match_root= */ NULL,
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

                if (asprintf(&mount_point, "unit-extensions/%zu", i) < 0)
                        return -ENOMEM;

                for (size_t j = 0; hierarchies && hierarchies[j]; ++j) {
                        char *prefixed_hierarchy = path_join(UNIT_STAGING_DIR, mount_point, hierarchies[j]);
                        if (!prefixed_hierarchy)
                                return -ENOMEM;

                        r = strv_consume(&overlays[j], TAKE_PTR(prefixed_hierarchy));
                        if (r < 0)
                                return r;
                }

                r = mount_append_entry(s, &(MountEntry) {
                                .path = mount_point,
                                .image_mount_options = m->mount_options,
                                .flags = m->ignore_enoent ? MOUNT_IGNORE : 0,
                                .source = result.path,
                                .kind = MOUNT_EXTENSION_IMAGE,
                                .verity = verity,
                                .filter_class = _IMAGE_CLASS_INVALID,
                        });
                if (r < 0)
                        return r;
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

                r = path_pick(/* root_path= */ NULL,
                              /* root_fd= */ AT_FDCWD,
                              /* dir_fd= */ AT_FDCWD,
                              e,
                              pick_filter_image_dir,
                              ELEMENTSOF(pick_filter_image_dir),
                              /* match_root= */ NULL,
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
                if (asprintf(&mount_point, "unit-extensions/%zu", n_mount_images++) < 0)
                        return -ENOMEM;

                for (size_t j = 0; hierarchies && hierarchies[j]; ++j) {
                        char *prefixed_hierarchy = path_join(UNIT_STAGING_DIR, mount_point, hierarchies[j]);
                        if (!prefixed_hierarchy)
                                return -ENOMEM;

                        r = strv_consume(&overlays[j], TAKE_PTR(prefixed_hierarchy));
                        if (r < 0)
                                return r;
                }

                r = mount_append_entry(s, &(MountEntry) {
                                .path = mount_point,
                                .source = result.path,
                                .kind = MOUNT_EXTENSION_DIRECTORY,
                                .flags = MOUNT_RDONLY | (ignore_enoent ? MOUNT_IGNORE : 0),
                                .filter_class = _IMAGE_CLASS_INVALID,
                        });
                if (r < 0)
                        return r;
        }

        /* Then, for each hierarchy, prepare an overlay with the list of lowerdir= strings
         * set up earlier. */
        for (size_t i = 0; hierarchies && hierarchies[i]; ++i) {
                r = mount_append_entry(s, &(MountEntry) {
                                .path = hierarchies[i],
                                .overlay_layers = overlays[i],
                                .kind = MOUNT_OVERLAY,
                                .flags = MOUNT_IGNORE, /* If the source image doesn't set the ignore bit it will fail earlier. */
                        });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_tmpfs_mounts(Set **s, const TemporaryFileSystem *tmpfs, size_t n) {
        assert(s);
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

                r = mount_append_entry(s, &(MountEntry) {
                                .path = t->path,
                                .kind = MOUNT_TMPFS,
                                .flags = ro ? MOUNT_RDONLY : 0,
                                .options = o,
                                .mount_flags = flags,
                        });
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_private_tmp_one(
                Set **s,
                PrivateTmp mode,
                const char *path,
                const char *connected_source,
                bool ignore) {

        assert(s);
        assert(mode >= 0 && mode < _PRIVATE_TMP_MAX);
        assert(path);

        if (mode == PRIVATE_TMP_NO)
                return 0;

        if (mode == PRIVATE_TMP_CONNECTED && !connected_source)
                /* Do nothing if the private tmp dir was suppressed as it would be made inaccessible anyways
                 * (see exec_shared_runtime_make()). */
                return 0;

        if (mode == PRIVATE_TMP_CONNECTED)
                return mount_append_entry(s, &(MountEntry) {
                                .path = (char*) path,
                                .kind = MOUNT_PRIVATE_TMP,
                                .flags = (ignore ? MOUNT_IGNORE : 0) |
                                         (streq(connected_source, RUN_SYSTEMD_EMPTY) ? MOUNT_RDONLY : 0),
                                .source = (char*) connected_source,
                        });

        return mount_append_entry(s, &(MountEntry) {
                        .path = (char*) path,
                        .kind = MOUNT_TMPFS,
                        .flags = MOUNT_IMPLICIT|(ignore ? MOUNT_IGNORE : 0),
                        .options = (char*) "mode=1777" NESTED_TMPFS_LIMITS,
                        .mount_flags = MS_NODEV|MS_STRICTATIME,
                });
}

static int append_private_tmp(Set **s, const NamespaceParameters *p) {
        int r;

        assert(s);
        assert(p);
        assert(p->private_tmp >= 0 && p->private_tmp < _PRIVATE_TMP_MAX);
        assert(p->private_var_tmp >= 0 && p->private_var_tmp < _PRIVATE_TMP_MAX);

        /* When a root file system is pinned, gracefully ignore the error if the /tmp/ and
         * /var/tmp/ mount points do not exist or cannot be created, e.g. on a read-only root
         * tree. */
        bool ignore = pinned_resource_is_set(p->rootfs);

        r = append_private_tmp_one(s, p->private_tmp, "/tmp/", p->tmp_dir, ignore);
        if (r < 0)
                return r;

        return append_private_tmp_one(s, p->private_var_tmp, "/var/tmp/", p->var_tmp_dir, ignore);
}

static int append_static_mounts(Set **s, const MountEntry *mounts, size_t n, bool ignore_protect) {
        int r;

        assert(s);
        assert(mounts || n == 0);

        /* Adds a list of static pre-defined entries */

        FOREACH_ARRAY(m, mounts, n) {
                /* No dynamic values allowed. */
                assert(m->path);
                assert(!m->overlay_layers);

                MountEntry copy = *m;

                /* All static tables define mounts implied by the sandboxing options, which explicit
                 * configuration shall be able to override. */
                copy.flags |= MOUNT_IMPLICIT;
                if (ignore_protect)
                        copy.flags |= MOUNT_IGNORE;

                r = mount_append_entry(s, &copy);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int append_protect_control_groups(Set **s, ProtectControlGroups protect_control_groups, bool ignore_protect) {
        assert(s);

        switch (protect_control_groups) {

        case PROTECT_CONTROL_GROUPS_NO:
                return 0;

        case PROTECT_CONTROL_GROUPS_YES:
                return append_static_mounts(s, protect_control_groups_yes_table, ELEMENTSOF(protect_control_groups_yes_table), ignore_protect);

        case PROTECT_CONTROL_GROUPS_PRIVATE:
                return append_static_mounts(s, protect_control_groups_private_table, ELEMENTSOF(protect_control_groups_private_table), ignore_protect);

        case PROTECT_CONTROL_GROUPS_STRICT:
                return append_static_mounts(s, protect_control_groups_strict_table, ELEMENTSOF(protect_control_groups_strict_table), ignore_protect);

        default:
                assert_not_reached();
        }
}

static int append_protect_home(Set **s, ProtectHome protect_home, bool ignore_protect) {
        assert(s);

        switch (protect_home) {

        case PROTECT_HOME_NO:
                return 0;

        case PROTECT_HOME_READ_ONLY:
                return append_static_mounts(s, protect_home_read_only_table, ELEMENTSOF(protect_home_read_only_table), ignore_protect);

        case PROTECT_HOME_TMPFS:
                return append_static_mounts(s, protect_home_tmpfs_table, ELEMENTSOF(protect_home_tmpfs_table), ignore_protect);

        case PROTECT_HOME_YES:
                return append_static_mounts(s, protect_home_yes_table, ELEMENTSOF(protect_home_yes_table), ignore_protect);

        default:
                assert_not_reached();
        }
}

static int append_protect_system(Set **s, ProtectSystem protect_system, bool ignore_protect) {
        assert(s);

        switch (protect_system) {

        case PROTECT_SYSTEM_NO:
                return 0;

        case PROTECT_SYSTEM_STRICT:
                return append_static_mounts(s, protect_system_strict_table, ELEMENTSOF(protect_system_strict_table), ignore_protect);

        case PROTECT_SYSTEM_YES:
                return append_static_mounts(s, protect_system_yes_table, ELEMENTSOF(protect_system_yes_table), ignore_protect);

        case PROTECT_SYSTEM_FULL:
                return append_static_mounts(s, protect_system_full_table, ELEMENTSOF(protect_system_full_table), ignore_protect);

        default:
                assert_not_reached();
        }
}

static int append_private_bpf(
                Set **s,
                PrivateBPF private_bpf,
                bool protect_kernel_tunables,
                bool ignore_protect,
                const NamespaceParameters *p) {

        int r;

        assert(s);

        switch (private_bpf) {
        case PRIVATE_BPF_NO:
                if (protect_kernel_tunables)
                        return append_static_mounts(s, private_bpf_no_table, ELEMENTSOF(private_bpf_no_table), ignore_protect);
                return 0;
        case PRIVATE_BPF_YES: {
                r = mount_append_entry(s, &(MountEntry) {
                                .path = (char*) "/sys/fs/bpf",
                                .kind = MOUNT_BPFFS,
                                /* Fall back to making it read-only on failure, if ProtectKernelTunables= is on */
                                .flags = MOUNT_IMPLICIT |
                                         (protect_kernel_tunables ? 0 : MOUNT_IGNORE),
                        });
                if (r < 0)
                        return r;

                return 0;
        }
        default:
                assert_not_reached();
        }
}

static bool verity_has_later_duplicates(MountEntry **entries, size_t n, size_t needle) {
        assert(entries || n == 0);
        assert(needle < n);
        assert(entries[needle]->kind == MOUNT_EXTENSION_IMAGE);

        if (!iovec_is_set(&entries[needle]->verity.root_hash))
                return false;

        /* Overlayfs rejects supplying the same directory inode twice as determined by filesystem UUID and
         * file handle in lowerdir=, even if they are mounted on different paths, as it resolves each mount
         * to its source filesystem, so drop duplicates, and keep the last one. This only covers non-DDI
         * verity images. Note that the array is ordered, so we only check for the remainder of the array
         * for each item, rather than the full array from the beginning, as any earlier duplicates will
         * have already been pruned. */

        for (size_t i = needle + 1; i < n; i++) {
                if (entries[i]->kind != MOUNT_EXTENSION_IMAGE)
                        continue;
                if (iovec_equal(&entries[i]->verity.root_hash, &entries[needle]->verity.root_hash))
                        return true;
        }

        return false;
}

static void drop_duplicate_extension_images(Set *s, MountEntry **entries, size_t *n_entries) {
        MountEntry **f, **t;

        assert(s);
        assert(entries);
        assert(n_entries);

        /* Drops the extension images that a later extension image duplicates by verity root hash.
         * Expects that the array is properly ordered already. */

        for (f = entries, t = entries; f < entries + *n_entries; f++) {
                if ((*f)->kind == MOUNT_EXTENSION_IMAGE &&
                    verity_has_later_duplicates(entries, *n_entries, f - entries)) {
                        log_debug("Skipping duplicate extension image %s", (*f)->source);
                        mount_entry_free(set_remove(s, *f));
                        continue;
                }

                *(t++) = *f;
        }

        *n_entries = t - entries;
}

static void drop_inaccessible(Set *s, MountEntry **entries, size_t *n_entries) {
        MountEntry **f, **t;
        const char *clear = NULL;

        assert(s);
        assert(entries);
        assert(n_entries);

        /* Drops all entries obstructed by another entry further up the tree. Expects that the array
         * is properly ordered already. */

        for (f = entries, t = entries; f < entries + *n_entries; f++) {

                /* If we found a path set for INACCESSIBLE earlier, and this entry has it as prefix we should drop
                 * it, as inaccessible paths really should drop the entire subtree. */
                if (clear && path_startswith((*f)->path, clear)) {
                        log_debug("%s is masked by %s.", (*f)->path, clear);
                        mount_entry_free(set_remove(s, *f));
                        continue;
                }

                clear = (*f)->kind == MOUNT_INACCESSIBLE ? (*f)->path : NULL;

                *(t++) = *f;
        }

        *n_entries = t - entries;
}

static void drop_nop(Set *s, MountEntry **entries, size_t *n_entries) {
        MountEntry **f, **t;

        assert(s);
        assert(entries);
        assert(n_entries);

        /* Drops all entries which have an immediate parent that has the same type, as they are
         * redundant. Assumes the array is ordered by prefixes. */

        for (f = entries, t = entries; f < entries + *n_entries; f++) {

                /* Only suppress such subtrees for the attribute-only entries */
                if ((*f)->kind == MOUNT_ADJUST) {
                        MountEntry *found = NULL;

                        /* Now let's find the first parent of the entry we are looking at. */
                        for (MountEntry **p = PTR_SUB1(t, entries); p; p = PTR_SUB1(p, entries))
                                if (path_startswith((*f)->path, (*p)->path)) {
                                        found = *p;
                                        break;
                                }

                        /* We found it, let's see if it's the same kind and flags, if so, we can
                         * drop this entry */
                        if (found && found->kind == (*f)->kind && found->flags == (*f)->flags) {
                                log_debug("%s (%s%s) is made redundant by %s (%s%s)",
                                          (*f)->path,
                                          FLAGS_SET((*f)->flags, MOUNT_IMPLICIT) ? "implicit " : "",
                                          kind_to_string((*f)->kind),
                                          found->path,
                                          FLAGS_SET(found->flags, MOUNT_IMPLICIT) ? "implicit " : "",
                                          kind_to_string(found->kind));
                                mount_entry_free(set_remove(s, *f));
                                continue;
                        }
                }

                *(t++) = *f;
        }

        *n_entries = t - entries;
}

static void drop_outside_root(Set *s, MountEntry **entries, size_t *n_entries) {
        MountEntry **f, **t;

        assert(s);
        assert(entries);
        assert(n_entries);

        /* Drops all mounts that are outside of the root directory. */

        for (f = entries, t = entries; f < entries + *n_entries; f++) {

                /* ExtensionImages/Directories bases are staged in a private tmpfs below
                 * /run/systemd/staging, outside of the root directory. */
                if (!IN_SET((*f)->kind, MOUNT_EXTENSION_IMAGE, MOUNT_EXTENSION_DIRECTORY) &&
                    !path_startswith((*f)->path, STAGING_ROOT_DIR)) {
                        log_debug("%s is outside of root directory.", (*f)->path);
                        mount_entry_free(set_remove(s, *f));
                        continue;
                }

                *(t++) = *f;
        }

        *n_entries = t - entries;
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
                mac_selinux_create_file_prepare(node, st.st_mode, /* label_context= */ NULL);
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
        r = mount_nofollow_verbose(LOG_DEBUG, node, dn, /* fstype= */ NULL, MS_BIND, /* options= */ NULL);
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
        return mount_nofollow_verbose(LOG_DEBUG, dir, t, /* fstype= */ NULL, MS_BIND, /* options= */ NULL);
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

        r = label_fix_full(AT_FDCWD, dev, "/dev", /* flags= */ 0, /* label_context= */ NULL);
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
        (void) mkdir_p_label(m->path, 0755);

        /* Unmount everything in old /dev */
        r = umount_recursive(m->path, /* flags= */ 0);
        if (r < 0)
                log_debug_errno(r, "Failed to unmount directories below '%s', ignoring: %m", m->path);

        r = mount_nofollow_verbose(LOG_DEBUG, dev, m->path, /* fstype= */ NULL, MS_MOVE, /* options= */ NULL);
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

        (void) mkdir_p_label(m->path, 0755);

        r = path_is_mount_point(m->path);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /dev is already mounted: %m");
        if (r > 0) /* make this a NOP if /dev is already a mount point */
                return 0;

        r = mount_nofollow_verbose(LOG_DEBUG, "/dev", m->path, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL);
        if (r < 0)
                return r;

        return 1;
}

static int mount_bind_sysfs(const MountEntry *m) {
        int r;

        assert(m);

        (void) mkdir_p_label(m->path, 0755);

        r = path_is_mount_point(m->path);
        if (r < 0)
                return log_debug_errno(r, "Unable to determine whether /sys is already mounted: %m");
        if (r > 0) /* make this a NOP if /sys is already a mount point */
                return 0;

        /* Bind mount the host's version so that we get all child mounts of it, too. */
        r = mount_nofollow_verbose(LOG_DEBUG, "/sys", m->path, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL);
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
        return mount_private_apivfs("sysfs", m->path, "/sys", /* opts= */ NULL, p->runtime_scope);
}

static int mount_private_cgroup2fs(const MountEntry *m, const NamespaceParameters *p) {
        assert(m);
        assert(p);
        return mount_private_apivfs("cgroup2", m->path, "/sys/fs/cgroup", /* opts= */ NULL, p->runtime_scope);
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
        return mount_private_apivfs("proc", m->path, "/proc", opts, p->runtime_scope);
}

static int mount_tmpfs(const MountEntry *m) {
        const char *entry_path, *inner_path;
        int r;

        assert(m);

        entry_path = m->path;
        inner_path = path_startswith_full(entry_path, STAGING_ROOT_DIR, PATH_STARTSWITH_RETURN_LEADING_SLASH) ?: entry_path;

        /* First, get rid of everything that is below if there is anything. Then, overmount with our new
         * tmpfs */

        (void) mkdir_p_label(entry_path, 0755);
        (void) umount_recursive(entry_path, /* flags= */ 0);

        r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", entry_path, "tmpfs", m->mount_flags, m->options);
        if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                return 0;
        if (r < 0)
                return r;

        r = label_fix_full(AT_FDCWD, entry_path, inner_path, /* flags= */ 0, /* label_context= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to fix label of '%s' as '%s': %m", entry_path, inner_path);

        return 1;
}

static int mount_mqueuefs(const MountEntry *m) {
        int r;
        const char *entry_path;

        assert(m);

        entry_path = m->path;

        (void) mkdir_p_label(entry_path, 0755);
        (void) umount_recursive(entry_path, /* flags= */ 0);

        r = mount_nofollow_verbose(LOG_DEBUG, "mqueue", entry_path, "mqueue", m->mount_flags, m->options);
        if (r == -ENODEV) /* POSIX message queues may be disabled in the kernel. */
                return 0;
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

        if (m->kind == MOUNT_EXTENSION_IMAGE) {
                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &rdata.os_release_id,
                                "ID_LIKE", &rdata.os_release_id_like,
                                "VERSION_ID", &rdata.os_release_version_id,
                                image_class_info[IMAGE_SYSEXT].level_env, &rdata.os_release_sysext_level,
                                image_class_info[IMAGE_CONFEXT].level_env, &rdata.os_release_confext_level,
                                "IMAGE_ID", &rdata.os_release_image_id,
                                "IMAGE_VERSION", &rdata.os_release_image_version,
                                NULL);
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'os-release' data of OS tree '%s': %m", empty_to_root(root_directory));
                if (isempty(rdata.os_release_id))
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "'ID' field not found or empty in 'os-release' data of OS tree '%s'.", empty_to_root(root_directory));

                required_class = m->filter_class;
        }

        r = verity_dissect_and_mount(
                        /* src_fd= */ -EBADF,
                        m->source,
                        m->path,
                        m->image_mount_options,
                        image_policy,
                        /* image_filter= */ NULL,
                        &rdata,
                        required_class,
                        &m->verity,
                        runtime_scope,
                        /* ret_image= */ NULL);
        if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                return 0;
        if (r == -ESTALE && rdata.os_release_id)
                return log_error_errno(r, // FIXME: this should not be logged ad LOG_ERR, as it will result in duplicate logging.
                                       "Failed to mount image %s, extension-release metadata does not match the lower layer's: ID=%s ID_LIKE='%s'%s%s%s%s%s%s%s%s%s%s",
                                       m->source,
                                       rdata.os_release_id,
                                       strempty(rdata.os_release_id_like),
                                       rdata.os_release_version_id ? " VERSION_ID=" : "",
                                       strempty(rdata.os_release_version_id),
                                       rdata.os_release_image_id ? " IMAGE_ID=" : "",
                                       strempty(rdata.os_release_image_id),
                                       rdata.os_release_image_version ? " IMAGE_VERSION=" : "",
                                       strempty(rdata.os_release_image_version),
                                       rdata.os_release_sysext_level ? image_class_info[IMAGE_SYSEXT].level_env_print : "",
                                       strempty(rdata.os_release_sysext_level),
                                       rdata.os_release_confext_level ? image_class_info[IMAGE_CONFEXT].level_env_print : "",
                                       strempty(rdata.os_release_confext_level));
        if (r == -ENOCSI) {
                log_debug("Image %s does not match the expected class, ignoring", m->source);
                return 0; /* Nothing to do, wrong class */
        }
        if (r < 0)
                return log_debug_errno(r, "Failed to mount image %s on %s: %m", m->source, m->path);

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
                          m->options);
                return 0; /* Only the root is set? Then there's nothing to overlay */
        }

        options = strjoin("lowerdir=", layers, ":", m->path); /* The root goes in last */
        if (!options)
                return log_oom_debug();

        (void) mkdir_p_label(m->path, 0755);

        r = mount_nofollow_verbose(LOG_DEBUG, "systemd-extensions", m->path, "overlay", MS_RDONLY, options);
        if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
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

        _cleanup_close_ int mnt_fd = fsmount(fs_fd, FSMOUNT_CLOEXEC, /* attr_flags= */ 0);
        if (mnt_fd < 0)
                return log_debug_errno(errno, "Failed to fsmount bpffs: %m");

        r = move_mount(mnt_fd, "", AT_FDCWD, m->path, MOVE_MOUNT_F_EMPTY_PATH);
        if (r < 0)
                return log_debug_errno(errno, "Failed to move bpffs mount to %s: %m", m->path);

        return 1;
}

static int follow_symlink(MountEntry *m) {
        _cleanup_free_ char *target = NULL;
        int r;

        assert(m);

        /* Let's chase symlinks, but only one step at a time. That's because depending where the symlink points we
         * might need to change the order in which we mount stuff. Hence: let's normalize piecemeal, and do one step at
         * a time by specifying CHASE_STEP. This function returns 0 if we resolved one step, and > 0 if we reached the
         * end and already have a fully normalized name. */

        r = chase(m->path, mount_entry_root_dir(m), CHASE_STEP|CHASE_NONEXISTENT|CHASE_TRIGGER_AUTOFS, &target, /* ret_fd= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to chase symlinks '%s': %m", m->path);
        if (r > 0) /* Reached the end, nothing more to resolve */
                return 1;

        if (m->n_followed >= CHASE_MAX) /* put a boundary on things */
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP),
                                       "Symlink loop on '%s'.",
                                       m->path);

        log_debug("Followed mount entry path symlink %s %s %s.",
                  m->path, glyph(GLYPH_ARROW_RIGHT), target);

        free_and_replace(m->path, target);

        m->n_followed++;

        return 0;
}

static int mount_bind(
                const MountEntry *m,
                const char *what,
                bool recursive,
                bool make) {

        int r;

        assert(m);
        assert(what);

        r = mount_nofollow_verbose(
                        LOG_DEBUG,
                        what,
                        m->path,
                        /* fstype= */ NULL,
                        MS_BIND|(recursive ? MS_REC : 0),
                        /* options= */ NULL);
        if (r >= 0)
                return 0;
        if (r != -ENOENT || !make)
                return log_debug_errno(r, "Failed to mount %s to %s: %m", what, m->path);

        /* Either the source or the destination is missing. Create the destination and try again. */
        r = mkdir_parents(m->path, 0755);
        if (r < 0 && r != -EEXIST) {
                if (FLAGS_SET(m->flags, MOUNT_IGNORE) && ERRNO_IS_NEG_FS_WRITE_REFUSED(r)) {
                        log_debug_errno(r, "Mount point '%s' cannot be created, ignoring: %m", m->path);
                        return 0;
                }

                return log_debug_errno(r,
                                       "Failed to create parent directories of destination mount point node '%s': %m",
                                       m->path);
        }

        r = make_mount_point_inode_from_path(what, m->path, 0755);
        if (r < 0 && r != -EEXIST) {
                if (FLAGS_SET(m->flags, MOUNT_IGNORE) && ERRNO_IS_NEG_FS_WRITE_REFUSED(r)) {
                        log_debug_errno(r, "Mount point '%s' cannot be created, ignoring: %m", m->path);
                        return 0;
                }

                return log_debug_errno(r, "Failed to create destination mount point node '%s': %m",
                                       m->path);
        }

        r = mount_nofollow_verbose(
                        LOG_DEBUG,
                        what,
                        m->path,
                        /* fstype= */ NULL,
                        MS_BIND|(recursive ? MS_REC : 0),
                        /* options= */ NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to mount %s to %s: %m", what, m->path);

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

        log_debug("Applying namespace mount on %s", m->path);

        if (m->kind == MOUNT_BPFFS) {
                r = mount_bpffs(m, p->bpffs_pidref, p->bpffs_socket_fd, p->bpffs_errno_pipe);
                if (r >= 0 ||
                    (!ERRNO_IS_NEG_NOT_SUPPORTED(r) && /* old kernel? */
                     !ERRNO_IS_NEG_PRIVILEGE(r)))      /* ubuntu kernel bug? See issue #38225 */
                        return r;

                if (FLAGS_SET(m->flags, MOUNT_IGNORE)) {
                        log_debug_errno(r, "Failed to mount new bpffs instance, ignoring: %m");
                        return 0;
                }

                log_debug_errno(r, "Failed to mount new bpffs instance at %s, will make read-only, ignoring: %m", m->path);
                m->kind = MOUNT_ADJUST;
                m->flags |= MOUNT_RDONLY|MOUNT_IGNORE;
        }

        switch (m->kind) {

        case MOUNT_INACCESSIBLE: {
                _cleanup_free_ char *runtime_dir = NULL;
                struct stat target;

                /* First, get rid of everything that is below if there
                 * is anything... Then, overmount it with an
                 * inaccessible path. */
                (void) umount_recursive(m->path, /* flags= */ 0);

                if (lstat(m->path, &target) < 0) {
                        if (errno == ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                                return 0;

                        return log_debug_errno(errno, "Failed to lstat() %s to determine what to mount over it: %m",
                                               m->path);
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

        case MOUNT_ADJUST:
                r = path_is_mount_point_full(m->path, root_directory, /* flags= */ 0);
                if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                        return 0;
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine whether %s is already a mount point: %m",
                                               m->path);
                if (r > 0) /* Nothing to do here, it is already a mount. We just later toggle the MS_RDONLY
                            * and MS_NOEXEC bits for the mount point if needed. */
                        return 1;
                /* This isn't a mount point yet, let's make it one. */
                what = m->path;
                break;

        case MOUNT_EXTENSION_DIRECTORY: {
                _cleanup_free_ char *host_os_release_id = NULL, *host_os_release_id_like = NULL,
                                *host_os_release_version_id = NULL, *host_os_release_level = NULL,
                                *host_os_release_image_id = NULL, *host_os_release_image_version = NULL,
                                *extension_name = NULL;
                _cleanup_strv_free_ char **extension_release = NULL;
                ImageClass class = IMAGE_SYSEXT;

                r = path_extract_filename(m->source, &extension_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to extract extension name from %s: %m", m->source);

                r = load_extension_release_pairs(
                                m->source,
                                m->filter_class >= 0 ? m->filter_class : IMAGE_SYSEXT,
                                extension_name,
                                /* relax_extension_release_check= */ false,
                                &extension_release);
                if (r == -ENOENT) {
                        if (m->filter_class >= 0)
                                return 0; /* Nothing to do, wrong class */

                        r = load_extension_release_pairs(
                                        m->source,
                                        IMAGE_CONFEXT,
                                        extension_name,
                                        /* relax_extension_release_check= */ false,
                                        &extension_release);
                        if (r >= 0)
                                class = IMAGE_CONFEXT;
                }
                if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                        return 0;
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire 'extension-release' data of extension tree %s: %m", m->source);

                r = parse_os_release(
                                empty_to_root(root_directory),
                                "ID", &host_os_release_id,
                                "ID_LIKE", &host_os_release_id_like,
                                "VERSION_ID", &host_os_release_version_id,
                                image_class_info[class].level_env, &host_os_release_level,
                                "IMAGE_ID", &host_os_release_image_id,
                                "IMAGE_VERSION", &host_os_release_image_version,
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
                                host_os_release_image_id,
                                host_os_release_image_version,
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

                r = chase(m->source, /* root= */ NULL, CHASE_TRAIL_SLASH|CHASE_TRIGGER_AUTOFS, &chased, /* ret_fd= */ NULL);
                if (r < 0) {
                        if (FLAGS_SET(m->flags, MOUNT_IGNORE)) {
                                if (r == -ENOENT) {
                                        log_debug_errno(r, "Path '%s' does not exist, ignoring.", m->source);
                                        return 0;
                                }
                                if (ERRNO_IS_NEG_PRIVILEGE(r)) {
                                        log_debug_errno(r, "Path '%s' is not accessible, ignoring: %m", m->source);
                                        return 0;
                                }
                        }

                        return log_debug_errno(r, "Failed to follow symlinks on %s: %m", m->source);
                }

                log_debug("Followed source symlinks %s %s %s.",
                          m->source, glyph(GLYPH_ARROW_RIGHT), chased);

                free_and_replace(m->source, chased);

                what = m->source;
                make = true;
                break;
        }

        case MOUNT_TMPFS:
                return mount_tmpfs(m);

        case MOUNT_PRIVATE_TMP:
                what = m->source;
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

        case MOUNT_CGROUP2FS:
                return mount_private_cgroup2fs(m, p);

        case MOUNT_MQUEUEFS:
                return mount_mqueuefs(m);

        case MOUNT_IMAGE:
                return mount_image(m, /* root_directory= */ NULL, p->mount_image_policy, p->runtime_scope);

        case MOUNT_EXTENSION_IMAGE:
                return mount_image(m, root_directory, p->extension_image_policy, p->runtime_scope);

        case MOUNT_OVERLAY:
                return mount_overlay(m);

        default:
                assert_not_reached();
        }

        assert(what);

        r = mount_bind(m, what, rbind, make);
        if (r < 0)
                return r;

        log_debug("Successfully mounted %s to %s", what, m->path);

        /* Take care of id-mapped mounts */
        if (m->idmapped && uid_is_valid(m->idmap_uid) && gid_is_valid(m->idmap_gid)) {
                _cleanup_close_ int userns_fd = -EBADF;
                _cleanup_free_ char *uid_map = NULL, *gid_map = NULL;

                log_debug("Setting an id-mapped mount on %s", m->path);

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
                r = remount_idmap_fd(STRV_MAKE(m->path), userns_fd, MOUNT_ATTR_NOSUID | MOUNT_ATTR_NOEXEC | MOUNT_ATTR_NODEV);
                if (r < 0)
                        return log_error_errno(r, "Failed to create an id-mapped mount: %m");

                log_debug("ID-mapped mount created successfully for %s from " UID_FMT " to " UID_FMT "", m->path, UID_NOBODY, m->idmap_uid);
        }

        return 1;
}

static bool should_propagate_to_submounts(const MountEntry *m) {
        assert(m);
        return m->kind != MOUNT_TMPFS;
}

static int make_read_only(const MountEntry *m, char **deny_list, FILE *proc_self_mountinfo) {
        unsigned long new_flags = 0, flags_mask = 0;
        bool submounts;
        int r;

        assert(m);
        assert(proc_self_mountinfo);

        if (m->state != MOUNT_APPLIED)
                return 0;

        if (FLAGS_SET(m->flags, MOUNT_RDONLY)) {
                new_flags |= MS_RDONLY;
                flags_mask |= MS_RDONLY;
        }

        if (FLAGS_SET(m->flags, MOUNT_NOSUID)) {
                new_flags |= MS_NOSUID;
                flags_mask |= MS_NOSUID;
        }

        if (flags_mask == 0) /* No Change? */
                return 0;

        /* We generally apply these changes recursively, except for /dev, and the cases we know there's
         * nothing further down.  Set /dev readonly, but not submounts like /dev/shm. Also, we only set the
         * per-mount read-only flag.  We can't set it on the superblock, if we are inside a user namespace
         * and running Linux <= 4.17. */
        submounts = FLAGS_SET(m->flags, MOUNT_RDONLY) && should_propagate_to_submounts(m);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(m->path, new_flags, flags_mask, deny_list, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(m->path, new_flags, flags_mask, proc_self_mountinfo);

        /* Note that we only turn on the MS_RDONLY flag here, we never turn it off. Something that was marked
         * read-only already stays this way. This improves compatibility with container managers, where we
         * won't attempt to undo read-only mounts already applied. */

        if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", m->path,
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

        if (FLAGS_SET(m->flags, MOUNT_NOEXEC)) {
                new_flags |= MS_NOEXEC;
                flags_mask |= MS_NOEXEC;
        } else if (FLAGS_SET(m->flags, MOUNT_EXEC)) {
                new_flags &= ~MS_NOEXEC;
                flags_mask |= MS_NOEXEC;
        }

        if (flags_mask == 0) /* No Change? */
                return 0;

        submounts = should_propagate_to_submounts(m);
        if (submounts)
                r = bind_remount_recursive_with_mountinfo(m->path, new_flags, flags_mask, deny_list, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(m->path, new_flags, flags_mask, proc_self_mountinfo);

        if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", m->path,
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
                r = bind_remount_recursive_with_mountinfo(m->path, MS_NOSUID, MS_NOSUID, /* deny_list= */ NULL, proc_self_mountinfo);
        else
                r = bind_remount_one_with_mountinfo(m->path, MS_NOSUID, MS_NOSUID, proc_self_mountinfo);
        if (r == -ENOENT && FLAGS_SET(m->flags, MOUNT_IGNORE))
                return 0;
        if (r < 0)
                return log_debug_errno(r, "Failed to re-mount '%s'%s: %m", m->path,
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
static int mount_set_normalize(Set **s) {
        _cleanup_free_ MountEntry **entries = NULL;
        size_t n;
        int r;

        assert(s);

        /* Sorts the registered entries and drops the redundant ones. */

        r = set_dump_sorted(*s, (void***) &entries, &n);
        if (r < 0)
                return r;

        drop_duplicate_extension_images(*s, entries, &n);
        drop_outside_root(*s, entries, &n);
        drop_inaccessible(*s, entries, &n);
        drop_nop(*s, entries, &n);

        return 0;
}

static int create_symlinks_from_tuples(char **strv_symlinks) {
        int r;

        STRV_FOREACH_PAIR(src, dst, strv_symlinks) {
                _cleanup_free_ char *src_abs = NULL, *dst_abs = NULL;

                src_abs = path_join(STAGING_ROOT_DIR, *src);
                dst_abs = path_join(STAGING_ROOT_DIR, *dst);
                if (!src_abs || !dst_abs)
                        return -ENOMEM;

                r = mkdir_parents_label(dst_abs, 0755);
                if (r < 0)
                        return log_debug_errno(
                                        r,
                                        "Failed to create parent directory for symlink '%s': %m",
                                        dst_abs);

                r = symlink_idempotent(src_abs, dst_abs, /* make_relative= */ true);
                if (r < 0)
                        return log_debug_errno(
                                        r,
                                        "Failed to create symlink from '%s' to '%s': %m",
                                        src_abs,
                                        dst_abs);
        }

        return 0;
}

static void mount_entry_path_debug_string(MountEntry *m, char **ret_path) {
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

        if (!m->path) {
                *ret_path = NULL;
                return;
        }

        const char *e = startswith(m->path, STAGING_ROOT_DIR);
        if (e) {
                *ret_path = strdup(e);
                return;
        }

        *ret_path = strdup(m->path);
        return;
}

static int setup_host_os_release(Set *s, const NamespaceParameters *p) {
        int r;

        assert(p);

        if (p->host_os_release_fd < 0)
                return 0;

        /* This is only done with MountAPIVFS= effectively enabled, hence /run/ must be the
         * private tmpfs: when the user overrode it with an explicitly configured mount, that
         * may point into the host, e.g. the inaccessible node, so refuse to write below it. */
        MountEntry *run = set_get(s, &(MountEntry) {
                        .path = (char*) STAGING_ROOT_DIR "/run",
                        .kind = MOUNT_TMPFS,
                });
        if (!run || run->kind != MOUNT_TMPFS)
                return 0;

        /* /run/host/ does not exist by default, so there must simply be no mount taking it
         * over either; attribute-only entries are fine. */
        MountEntry *run_host = set_get(s, &(MountEntry) {
                        .path = (char*) STAGING_ROOT_DIR "/run/host",
                        .kind = MOUNT_TMPFS,
                });
        if (run_host && !IN_SET(run_host->kind, MOUNT_TMPFS, MOUNT_ADJUST))
                return 0;

        _cleanup_close_ int dir_fd = -EBADF;
        r = chase("run/host", STAGING_ROOT_DIR,
                  CHASE_PREFIX_ROOT|CHASE_MKDIR_0755|CHASE_PROHIBIT_SYMLINKS,
                  /* ret_path= */ NULL, &dir_fd);
        if (r < 0)
                return r;

        _cleanup_close_ int fdt = xopenat_full(dir_fd, "os-release", O_WRONLY|O_CREAT|O_EXCL|O_NOCTTY, XO_LABEL, 0644);
        if (fdt == -EEXIST) {
                log_debug("/run/host/os-release already exists, ignoring.");
                return 0;
        }
        if (fdt < 0)
                return fdt;

        return copy_bytes(p->host_os_release_fd, fdt, /* max_bytes= */ UINT64_MAX, /* copy_flags= */ 0);
}

static int apply_mounts(
                Set **s,
                const NamespaceParameters *p,
                char **reterr_path) {

        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        _cleanup_free_ char **deny_list = NULL;
        int r;

        assert(s);
        assert(p);

        if (set_isempty(*s)) /* Shortcut: nothing to do */
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
                _cleanup_free_ MountEntry **entries = NULL;
                size_t n;
                bool again = false;

                r = set_dump_sorted(*s, (void***) &entries, &n);
                if (r < 0)
                        return r;

                FOREACH_ARRAY(me, entries, n) {
                        MountEntry *m = *me;

                        if (m->state != MOUNT_PENDING)
                                continue;

                        /* Take the entry out of the set for now: follow_symlink() may rewrite its
                         * path, and it is re-registered under the new one then. */
                        set_remove(*s, m);

                        r = follow_symlink(m);
                        if (r < 0) {
                                mount_entry_path_debug_string(m, reterr_path);
                                mount_entry_free(m);
                                return r;
                        }
                        if (r == 0) {
                                /* We hit a symlinked mount point. The entry got rewritten and might
                                 * point to a very different place now. Let's register it again under
                                 * the new path, and start from the beginning. After all to mount the
                                 * entry at the new location we might need some other mounts first */
                                r = mount_append_entry_consume(s, m);
                                if (r < 0)
                                        return r;

                                again = true;
                                break;
                        }

                        r = set_ensure_consume(s, &mount_entry_hash_ops, m);
                        if (r < 0)
                                return r;

                        /* Returns 1 if the mount should be post-processed, 0 otherwise */
                        r = apply_one_mount(STAGING_ROOT_DIR, m, p);
                        if (r < 0) {
                                mount_entry_path_debug_string(m, reterr_path);
                                return r;
                        }
                        m->state = r == 0 ? MOUNT_SKIPPED : MOUNT_APPLIED;
                }

                if (!again)
                        break;
        }

        /* Now that all filesystems have been set up, but before the
         * read-only switches are flipped, create the exec dirs and other symlinks.
         * Note that when /var/lib is not empty/tmpfs, these symlinks will already
         * exist, which means this will be a no-op. */
        r = create_symlinks_from_tuples(p->symlinks);
        if (r < 0)
                return log_debug_errno(r, "Failed to set up symlinks inside mount namespace: %m");

        r = setup_host_os_release(*s, p);
        if (r < 0)
                log_debug_errno(r, "Failed to set up the host's os-release, ignoring: %m");

        _cleanup_free_ MountEntry **entries = NULL;
        size_t n;

        r = set_dump_sorted(*s, (void***) &entries, &n);
        if (r < 0)
                return r;

        /* Create a deny list we can pass to bind_mount_recursive() */
        deny_list = new(char*, n+1);
        if (!deny_list)
                return -ENOMEM;
        size_t k = 0;
        FOREACH_ARRAY(m, entries, n)
                deny_list[k++] = (*m)->path;
        deny_list[k] = NULL;

        /* Second round, flip the ro bits if necessary. */
        FOREACH_ARRAY(m, entries, n) {
                r = make_read_only(*m, deny_list, proc_self_mountinfo);
                if (r < 0) {
                        mount_entry_path_debug_string(*m, reterr_path);
                        return r;
                }
        }

        /* Third round, flip the noexec bits with a simplified deny list. */
        k = 0;
        FOREACH_ARRAY(m, entries, n)
                if (((*m)->flags & (MOUNT_NOEXEC|MOUNT_EXEC)) || FLAGS_SET((*m)->mount_flags, MS_NOEXEC))
                        deny_list[k++] = (*m)->path;
        deny_list[k] = NULL;

        FOREACH_ARRAY(m, entries, n) {
                r = make_noexec(*m, deny_list, proc_self_mountinfo);
                if (r < 0) {
                        mount_entry_path_debug_string(*m, reterr_path);
                        return r;
                }
        }

        /* Fourth round, flip the nosuid bits without a deny list. */
        if (p->mount_nosuid)
                FOREACH_ARRAY(m, entries, n) {
                        r = make_nosuid(*m, proc_self_mountinfo);
                        if (r < 0) {
                                mount_entry_path_debug_string(*m, reterr_path);
                                return r;
                        }
                }

        return 1;
}

static bool root_read_only(const NamespaceParameters *p) {

        /* Determine whether the root directory is going to be read-only given the configured settings. */

        if (p->protect_system == PROTECT_SYSTEM_STRICT)
                return true;

        FOREACH_ARRAY(a, p->access_mounts, p->n_access_mounts)
                if (a->mode == ACCESS_MOUNT_READ_ONLY && path_equal(a->path, "/"))
                        return true;

        return false;
}

static bool home_read_only(const NamespaceParameters *p) {

        /* Determine whether the /home directory is going to be read-only given the configured settings. Yes,
         * this is a bit sloppy, since we don't bother checking for cases where / is affected by multiple
         * settings. */

        if (p->protect_home != PROTECT_HOME_NO)
                return true;

        FOREACH_ARRAY(a, p->access_mounts, p->n_access_mounts)
                if (IN_SET(a->mode, ACCESS_MOUNT_READ_ONLY, ACCESS_MOUNT_INACCESSIBLE) &&
                    path_equal(a->path, "/home"))
                        return true;

        if (prefixed_path_strv_contains(p->empty_directories, "/home"))
                return true;

        FOREACH_ARRAY(i, p->temporary_filesystems, p->n_temporary_filesystems)
                if (path_equal(i->path, "/home"))
                        return true;

        /* If /home is overmounted with some dir from the host it's not writable. */
        FOREACH_ARRAY(i, p->bind_mounts, p->n_bind_mounts)
                if (path_equal(i->destination, "/home"))
                        return true;

        return false;
}

static bool namespace_read_only(const NamespaceParameters *p) {
        assert(p);

        FOREACH_ARRAY(a, p->access_mounts, p->n_access_mounts)
                if (a->mode == ACCESS_MOUNT_READ_WRITE)
                        return false;

        return root_read_only(p) && home_read_only(p);
}

int setup_namespace(const NamespaceParameters *p, char **reterr_path) {

        _cleanup_(loop_device_unrefp) LoopDevice *loop_device = NULL;
        _cleanup_(dissected_image_unrefp) DissectedImage *dissected_image = NULL;
        _cleanup_strv_free_ char **hierarchies = NULL;
        _cleanup_set_free_ Set *entries = NULL;
        _cleanup_close_ int userns_fd = -EBADF;
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

                        /* Try to clone the directory mount if we have privs to, so that we can apply the
                         * MS_SLAVE propagation settings right-away. */
                        if (root_mount_fd < 0) {
                                _root_mount_fd = open_tree_attr_with_fallback(
                                                p->rootfs->directory_fd,
                                                "",
                                                OPEN_TREE_CLONE|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH|AT_RECURSIVE,
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

        /* /run/systemd should have been created by PID 1 early on already, but in some cases, like
         * when running tests (test-execute), it might not have been created yet so let's make sure
         * we create it if it doesn't already exist. */
        (void) mkdir_p_label("/run/systemd", 0755);

        /* Always create the mount namespace in a temporary directory, instead of operating directly
         * in the root (also when a root directory is configured). The temporary directory prevents any
         * mounts from being potentially obscured by other mounts we already applied — in particular,
         * bind mount sources below paths that are overmounted before them, such as the log sockets
         * below /run/, whose sources are resolved at application time. We use the same mount point
         * for all images, which is safe, since they all live in their own namespaces after all, and
         * hence won't see each other. (Note: this directory is also created by PID 1 early on, we
         * create it here for similar reasons as /run/systemd/ first.) */
        (void) mkdir_label(STAGING_ROOT_DIR, 0555);

        /* Same as above: the mount point for the private staging tmpfs is created by PID 1 early
         * on, but let's make sure it exists also in the cases where that did not happen. */
        (void) mkdir_label(UNIT_STAGING_DIR, 0555);

        if (p->n_extension_images > 0 || !strv_isempty(p->extension_directories)) {
                /* Hierarchy population needs to be done for sysext and confext extension images */
                r = parse_env_extension_hierarchies(&hierarchies, "SYSTEMD_SYSEXT_AND_CONFEXT_HIERARCHIES");
                if (r < 0)
                        return r;
        }

        r = append_access_mounts(&entries, p->access_mounts, p->n_access_mounts);
        if (r < 0)
                return r;

        r = append_empty_dir_mounts(&entries, p->empty_directories);
        if (r < 0)
                return r;

        r = append_bind_mounts(&entries, p->bind_mounts, p->n_bind_mounts, /* implicit= */ false);
        if (r < 0)
                return r;

        r = append_tmpfs_mounts(&entries, p->temporary_filesystems, p->n_temporary_filesystems);
        if (r < 0)
                return r;

        r = append_private_tmp(&entries, p);
        if (r < 0)
                return r;

        r = append_mount_images(&entries, p->mount_images, p->n_mount_images);
        if (r < 0)
                return r;

        r = append_extensions(&entries, hierarchies, p->extension_images, p->n_extension_images, p->extension_directories);
        if (r < 0)
                return r;

        if (p->private_dev) {
                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) "/dev",
                                .kind = MOUNT_PRIVATE_DEV,
                                .flags = MOUNT_IMPLICIT,
                                .mount_flags = DEV_MOUNT_OPTIONS,
                        });
                if (r < 0)
                        return r;
        }

        /* In case /proc is successfully mounted with pid tree subset only (ProcSubset=pid), the protective
           mounts to non-pid /proc paths would fail. But the pid only option may have failed gracefully, so
           let's try the mounts but it's not fatal if they don't succeed. */
        bool ignore_protect_proc = p->ignore_protect_paths || p->proc_subset == PROC_SUBSET_PID;
        if (p->protect_kernel_tunables) {
                r = append_static_mounts(&entries,
                                         protect_kernel_tunables_proc_table,
                                         ELEMENTSOF(protect_kernel_tunables_proc_table),
                                         ignore_protect_proc);
                if (r < 0)
                        return r;

                r = append_static_mounts(&entries,
                                         protect_kernel_tunables_sys_table,
                                         ELEMENTSOF(protect_kernel_tunables_sys_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        if (p->protect_kernel_modules) {
                r = append_static_mounts(&entries,
                                         protect_kernel_modules_table,
                                         ELEMENTSOF(protect_kernel_modules_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        if (p->protect_kernel_logs) {
                r = append_static_mounts(&entries,
                                         protect_kernel_logs_proc_table,
                                         ELEMENTSOF(protect_kernel_logs_proc_table),
                                         ignore_protect_proc);
                if (r < 0)
                        return r;

                r = append_static_mounts(&entries,
                                         protect_kernel_logs_dev_table,
                                         ELEMENTSOF(protect_kernel_logs_dev_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;
        }

        r = append_protect_control_groups(&entries, p->protect_control_groups, /* ignore_protect= */ false);
        if (r < 0)
                return r;

        r = append_protect_home(&entries, p->protect_home, p->ignore_protect_paths);
        if (r < 0)
                return r;

        r = append_protect_system(&entries, p->protect_system, /* ignore_protect= */ false);
        if (r < 0)
                return r;

        r = append_private_bpf(&entries, p->private_bpf, p->protect_kernel_tunables, /* ignore_protect= */ false, p);
        if (r < 0)
                return r;

        if (namespace_parameters_mount_apivfs(p)) {
                r = append_static_mounts(&entries,
                                         apivfs_table,
                                         ELEMENTSOF(apivfs_table),
                                         p->ignore_protect_paths);
                if (r < 0)
                        return r;

                /* Only set up a writable /run/ tmpfs when a separate root directory is used. Without one, /run/
                 * is the host's; leaving it out here keeps it subject to the read-only remount of
                 * ProtectSystem=strict (and avoids leaking the host's /run/ as writable). A writable /run/ (or
                 * a subdirectory of it) can still be requested via ReadWritePaths= or RuntimeDirectory=. */
                if (pinned_resource_is_set(p->rootfs)) {
                        r = append_static_mounts(&entries,
                                                 apivfs_run_table,
                                                 ELEMENTSOF(apivfs_run_table),
                                                 p->ignore_protect_paths);
                        if (r < 0)
                                return r;
                }
        }

        /* Only mount /proc/sys/kernel/hostname and domainname read-only if ProtectHostname=yes. Otherwise,
         * ProtectHostname=no allows changing hostname for the host, and ProtectHostname=private allows
         * changing the hostname in the unit's UTS namespace. Note, if proc is mounted with subset=pid then
         * neither of the two paths will exist, i.e. they are implicitly protected by the mount option. */
        if (p->protect_hostname == PROTECT_HOSTNAME_YES) {
                r = append_static_mounts(
                                &entries,
                                protect_hostname_yes_table,
                                ELEMENTSOF(protect_hostname_yes_table),
                                ignore_protect_proc);
                if (r < 0)
                        return r;
        }

        if (p->private_network) {
                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) "/sys",
                                .kind = MOUNT_PRIVATE_SYSFS,
                                .flags = MOUNT_IMPLICIT,
                        });
                if (r < 0)
                        return r;
        }

        if (p->private_ipc) {
                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) "/dev/mqueue",
                                .kind = MOUNT_MQUEUEFS,
                                .flags = MOUNT_IMPLICIT,
                                .mount_flags = MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME,
                        });
                if (r < 0)
                        return r;
        }

        if (p->creds_path) {
                /* If our service has a credentials store configured, then bind that one in, but hide
                 * everything else. */

                _cleanup_free_ char *credentials_dir_malloc = NULL;
                const char *credentials_dir = "/run/credentials";

                if (p->runtime_scope != RUNTIME_SCOPE_SYSTEM) {
                        r = path_extract_directory(p->creds_path, &credentials_dir_malloc);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to extract parent directory from '%s': %m",
                                                       p->creds_path);
                        credentials_dir = credentials_dir_malloc;
                }

                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) credentials_dir,
                                .kind = MOUNT_TMPFS,
                                .flags = MOUNT_RDONLY,
                                .options = (char*) "mode=0755" TMPFS_LIMITS_EMPTY_OR_ALMOST,
                                .mount_flags = MS_NODEV|MS_STRICTATIME|MS_NOSUID|MS_NOEXEC,
                        });
                if (r < 0)
                        return r;

                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) p->creds_path,
                                .kind = MOUNT_BIND,
                                .flags = MOUNT_RDONLY,
                                .source = (char*) p->creds_path,
                        });
                if (r < 0)
                        return r;
        }

        if (!p->creds_path || p->runtime_scope != RUNTIME_SCOPE_SYSTEM) {
                /* If our service has no credentials store configured, or we're running in user scope, then
                 * make the system credentials tree inaccessible wholesale. */

                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) "/run/credentials",
                                .kind = MOUNT_INACCESSIBLE,
                                .flags = MOUNT_IMPLICIT|MOUNT_RDONLY|MOUNT_NOEXEC|MOUNT_IGNORE,
                        });
                if (r < 0)
                        return r;
        }

        if (p->log_namespace) {
                _cleanup_free_ char *q = NULL;

                q = strjoin("/run/systemd/journal.", p->log_namespace);
                if (!q)
                        return log_oom_debug();

                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) "/run/systemd/journal",
                                .kind = MOUNT_BIND_RECURSIVE,
                                .flags = MOUNT_RDONLY,
                                .source = q,
                        });
                if (r < 0)
                        return r;

        } else if (p->bind_log_sockets) {
                r = append_bind_mounts(&entries, bind_log_sockets_table,
                                       ELEMENTSOF(bind_log_sockets_table), /* implicit= */ true);
                if (r < 0)
                        return r;
        }

        /* Will be used to add bind mounts at runtime */
        if (setup_propagate) {
                r = mount_append_entry(&entries, &(MountEntry) {
                                .source = (char*) p->propagate_dir,
                                .path = (char*) p->incoming_dir,
                                .kind = MOUNT_BIND,
                                .flags = MOUNT_RDONLY,
                        });
                if (r < 0)
                        return r;
        }

        if (p->notify_socket_path) {
                r = mount_append_entry(&entries, &(MountEntry) {
                                .path = (char*) p->notify_socket_path,
                                .source = (char*) p->host_notify_socket,
                                .kind = MOUNT_BIND,
                                .flags = MOUNT_RDONLY,
                        });
                if (r < 0)
                        return r;
        }

        r = mount_set_normalize(&entries);
        if (r < 0)
                return r;

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

        /* Remount / as SLAVE so that nothing now mounted in the namespace
         * shows up in the parent */
        r = mount_nofollow_verbose(LOG_DEBUG, /* what= */ NULL, "/", /* fstype= */ NULL, MS_SLAVE|MS_REC, /* options= */ NULL);
        if (r < 0)
                return r;

        if (p->n_extension_images > 0 || !strv_isempty(p->extension_directories)) {
                /* Mount a private tmpfs to stage the extensions in. This is done in the mount
                 * namespace we just unshared and made a slave, hence it stays private to the
                 * unit, and it works no matter which user namespace the unit runs in. */
                r = mount_nofollow_verbose(LOG_DEBUG, "tmpfs", UNIT_STAGING_DIR, "tmpfs",
                                           MS_NODEV|MS_NOSUID, "mode=0700" TMPFS_LIMITS_EMPTY_OR_ALMOST);
                if (r < 0)
                        return r;

                /* ExtensionImages/Directories mountpoint directories will be created while parsing the
                 * mounts to create, so have the parent ready */
                (void) mkdir_p(UNIT_STAGING_DIR "/unit-extensions", 0600);
        }

        if (root_mount_fd >= 0) {
                /* If we have root_mount_fd we have a ready-to-use detached mount. Attach it. */

                if (move_mount(root_mount_fd, "", AT_FDCWD, STAGING_ROOT_DIR, MOVE_MOUNT_F_EMPTY_PATH) < 0)
                        return log_debug_errno(errno, "Failed to move detached mount to '%s': %m", STAGING_ROOT_DIR);

                r = mount_nofollow_verbose(LOG_DEBUG, /* what= */ NULL, STAGING_ROOT_DIR, /* fstype= */ NULL, MS_SLAVE|MS_REC, /* options= */ NULL);
                if (r < 0)
                        return r;

        } else if (dissected_image) {

                /* A root image is specified, mount it to the right place */
                r = dissected_image_mount(
                                dissected_image,
                                STAGING_ROOT_DIR,
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

                r = mstack_make_mounts(p->rootfs->mstack_loaded, STAGING_ROOT_DIR, mstack_flags);
                if (r < 0)
                        return r;

                r = mstack_bind_mounts(p->rootfs->mstack_loaded, STAGING_ROOT_DIR, /* where_fd= */ -EBADF, mstack_flags, /* ret_root_fd= */ NULL);
                if (r < 0)
                        return r;

        } else {
                /* Bind the main root directory (the configured one, or our own root when none is
                 * configured) to the staging directory. This is the fallback for a root directory when
                 * we could not get a detached mount of it, e.g. in an unprivileged user manager. Bind
                 * by path: the pinned fd was opened before the mount namespace was unshared, and binds
                 * through /proc/self/fd/ of such an fd fail with EINVAL as the fd references a mount of
                 * the old mount namespace. */
                r = mount_nofollow_verbose(LOG_DEBUG,
                                           p->rootfs && p->rootfs->directory ? p->rootfs->directory : "/",
                                           STAGING_ROOT_DIR, /* fstype= */ NULL, MS_BIND|MS_REC, /* options= */ NULL);
                if (r < 0)
                        return r;
        }

        /* Try to set up the new root directory before mounting anything else there. */
        if (pinned_resource_is_set(p->rootfs))
                (void) base_filesystem_create(STAGING_ROOT_DIR, UID_INVALID, GID_INVALID);

        /* Now make the magic happen */
        r = apply_mounts(&entries, p, reterr_path);
        if (r < 0)
                return r;

        /* MS_MOVE does not work on MS_SHARED so the remount MS_SHARED will be done later */
        r = mount_switch_root(STAGING_ROOT_DIR, /* mount_propagation_flag = */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to mount root with MS_MOVE: %m");

        /* Remount / as the desired mode. Note that this will not reestablish propagation from our side to
         * the host, since what's disconnected is disconnected. */
        if (mount(/* source= */ NULL, "/", /* filesystemtype= */ NULL, mount_propagation_flag | MS_REC, /* data= */ NULL) < 0)
                return log_debug_errno(errno, "Failed to remount '/' with desired mount flags: %m");

        /* bind_mount_in_namespace() will MS_MOVE into that directory, and that's only supported for
         * non-shared mounts. This needs to happen after remounting / or it will fail. */
        if (setup_propagate && mount(/* source= */ NULL, p->incoming_dir, /* filesystemtype= */ NULL, MS_SLAVE, /* data= */ NULL) < 0)
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

void access_mount_free_many(AccessMount *a, size_t n) {
        assert(a || n == 0);

        FOREACH_ARRAY(i, a, n)
                free(i->path);

        free(a);
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

static void mount_image_done(MountImage *m) {
        assert(m);
        m->source = mfree(m->source);
        m->destination = mfree(m->destination);
        m->mount_options = mount_options_free_all(m->mount_options);
}

DEFINE_ARRAY_FREE_FUNC(mount_image_free_array, MountImage, mount_image_done);

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

char* namespace_cleanup_tmpdir(char *p) {
        if (!p)
                return NULL;

        if (!streq(p, RUN_SYSTEMD_EMPTY)) {
                _cleanup_free_ char *child = path_join(p, "tmp");
                if (!child)
                        log_oom_debug();
                else
                        (void) rmdir(child);

                (void) rmdir(p);
        }

        return mfree(p);
}

static int make_tmp_prefix(const char *prefix) {
        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(prefix);

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

        r = tempfn_random(prefix, /* extra= */ NULL, &t);
        if (r < 0)
                return r;

        /* umask will corrupt this access mode, but that doesn't matter, we need to call chmod() anyway for
         * the suid bit, below. */
        fd = open_mkdir(t, O_EXCL, 0777);
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
                return IN_SET(r, -EEXIST, -ENOTEMPTY) ? 0 : r; /* it's fine if someone else created the dir by now */
        }

        return 0;
}

int setup_tmp_dir_one(const char *id, const char *prefix, char **ret_path) {
        _cleanup_free_ char *d = NULL;
        sd_id128_t boot_id;
        bool rw = true;
        int r;

        assert(id);
        assert(prefix);
        assert(ret_path);

        /* We include the boot id in the directory so that after a
         * reboot we can easily identify obsolete directories. */

        r = sd_id128_get_boot(&boot_id);
        if (r < 0)
                return r;

        d = strjoin(prefix, "/systemd-private-", SD_ID128_TO_STRING(boot_id), "-", id, "-XXXXXX");
        if (!d)
                return -ENOMEM;

        r = make_tmp_prefix(prefix);
        if (r < 0)
                return r;

        WITH_UMASK(0077)
                if (!mkdtemp(d)) {
                        if (errno == EROFS || ERRNO_IS_DISK_SPACE(errno))
                                rw = false;
                        else
                                return -errno;
                }

        if (rw) {
                _cleanup_free_ char *inner_dir = path_join(d, "tmp");
                if (!inner_dir) {
                        (void) rmdir(d);
                        return -ENOMEM;
                }

                WITH_UMASK(0000)
                        r = RET_NERRNO(mkdir(inner_dir, 0777 | S_ISVTX));
                if (r < 0) {
                        (void) rmdir(d);
                        return r;
                }

                r = label_fix_full(AT_FDCWD, inner_dir, prefix, /* flags= */ 0, /* label_context= */ NULL);
                if (r < 0) {
                        (void) rmdir(inner_dir);
                        (void) rmdir(d);
                        return r;
                }
        } else {
                /* Trouble: we failed to create the directory. Instead of failing, let's simulate /tmp being
                 * read-only. This way the service will get the EROFS result as if it was writing to the real
                 * file system. */
                WITH_UMASK(0000)
                        r = mkdir_p(RUN_SYSTEMD_EMPTY, 0500);
                if (r < 0)
                        return r;

                r = free_and_strdup(&d, RUN_SYSTEMD_EMPTY);
                if (r < 0)
                        return r;
        }

        *ret_path = TAKE_PTR(d);
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
        ns = xopenat(AT_FDCWD, ns_path, O_RDONLY|O_NOCTTY);
        if (ns < 0)
                return ns;

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

        ns = xopenat(AT_FDCWD, path, O_RDONLY|O_NOCTTY);
        if (ns < 0)
                return ns;

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
                dir_fd = open_tree(-EBADF, mount_path, AT_SYMLINK_NOFOLLOW|OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);
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
                        log_debug("'%s' is still an overlay after opening mount tree", mount_path);
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

        r = receive_one_fd(pipe_fds[0], /* flags= */ 0);
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
        r = receive_one_fd(pair_fd, /* flags= */ 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to receive configured overlay: %m");

        /* Create the mount */
        mount_fd = fsmount(overlay_fs_fd, FSMOUNT_CLOEXEC, /* attr_flags= */ 0);
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
                MountEntry **entries,
                size_t n_entries,
                int pidns_fd,
                int mntns_fd,
                int root_fd,
                int pipe_fd) {

        int r;

        assert(pidref_is_set(target));
        assert(entries || n_entries == 0);
        assert(pidns_fd >= 0);
        assert(mntns_fd >= 0);
        assert(root_fd >= 0);
        assert(pipe_fd >= 0);

        r = namespace_enter(pidns_fd, mntns_fd, /* netns_fd= */ -EBADF, /* userns_fd= */ -EBADF, root_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to enter namespace: %m");

        /* Handle each overlay mount path */
        FOREACH_ARRAY(me, entries, n_entries) {
                MountEntry *m = *me;

                if (m->kind != MOUNT_OVERLAY)
                        continue;

                /* Need an absolute path under the child namespace, rather than the root's */
                _cleanup_free_ char *mount_path = NULL;
                mount_path = path_join("/", path_startswith(m->path, STAGING_ROOT_DIR) ?: m->path);
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
                int **fd_layers,
                size_t *n_fd_layers,
                int pipe_fd) {

        _cleanup_free_ char *layers = NULL, *options = NULL, *hierarchy_path_moved_mount = NULL;
        _cleanup_close_ int hierarchy_path_fd = -EBADF, overlay_fs_fd = -EBADF;
        _cleanup_strv_free_ char **new_layers = NULL;
        int r;

        assert(m);
        assert(fd_layers);
        assert(n_fd_layers);
        assert(pipe_fd >= 0);

        if (m->kind != MOUNT_OVERLAY)
                return 0;

        const char *mount_path = path_startswith(m->path, STAGING_ROOT_DIR) ?: m->path;

        /* If there are no extensions mounted for this overlay layer, we only need to
        * unmount the existing overlay (this is handled in the grandchild process) and
        * would skip the usual cooperative processing here.
        */
        if (strv_isempty(m->overlay_layers)) {
                log_debug("No layers for %s, skip setting up overlay", mount_path);
                return 0;
        }

        /* Receive the fds from grandchild */
        overlay_fs_fd = receive_one_fd(pipe_fd, /* flags= */ 0);
        if (overlay_fs_fd < 0)
                return log_debug_errno(overlay_fs_fd, "Failed to receive overlay fs fd from grandchild: %m");

        hierarchy_path_fd = receive_one_fd(pipe_fd, /* flags= */ 0);
        if (hierarchy_path_fd < 0)
                return log_debug_errno(hierarchy_path_fd, "Failed to receive fd from grandchild for %s: %m", mount_path);

        /* move_mount so that it is visible on our end. */
        hierarchy_path_moved_mount = path_join(STAGING_ROOT_DIR, mount_path);
        if (!hierarchy_path_moved_mount)
                return log_oom_debug();

        (void) mkdir_p_label(hierarchy_path_moved_mount, 0555);
        r = RET_NERRNO(move_mount(hierarchy_path_fd, "", AT_FDCWD, hierarchy_path_moved_mount, MOVE_MOUNT_F_EMPTY_PATH));
        if (r < 0)
                return log_debug_errno(r, "Failed to move mount for %s: %m", mount_path);

        /* Turn all overlay layer directories into FD-based references */
        if (!GREEDY_REALLOC(*fd_layers, *n_fd_layers + strv_length(m->overlay_layers)))
                return log_oom_debug();

        STRV_FOREACH(ol, m->overlay_layers) {
                _cleanup_close_ int tree_fd = -EBADF;

                tree_fd = open_tree(-EBADF, *ol, OPEN_TREE_CLOEXEC);
                if (tree_fd < 0)
                        return log_debug_errno(errno, "Failed to open_tree overlay layer '%s': %m", *ol);

                r = strv_extend(&new_layers, FORMAT_PROC_FD_PATH(tree_fd));
                if (r < 0)
                        return log_oom_debug();

                (*fd_layers)[(*n_fd_layers)++] = TAKE_FD(tree_fd);
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

        if (fsconfig(overlay_fs_fd, FSCONFIG_SET_STRING, "lowerdir", options, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to set lowerdir=%s: %m", options);

        if (fsconfig(overlay_fs_fd, FSCONFIG_SET_STRING, "source", "systemd-extensions", /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to set source=systemd-extensions: %m");

        /* Create the superblock */
        if (fsconfig(overlay_fs_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to create overlay superblock: %m");

        /* Signal completion to grandchild */
        r = send_one_fd(pipe_fd, overlay_fs_fd, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to signal overlay configuration complete for %s: %m", mount_path);

        return 0;
}

static int refresh_apply_and_prune(const NamespaceParameters *p, Set **s, MountEntry **entries, size_t *n_entries) {
        int r;

        assert(p);
        assert(s);
        assert(n_entries);
        assert(entries || *n_entries == 0);

        /* Open all extensions on the host, drop all sysexts since they won't have /etc/. The list of
         * overlays also need to be updated, so that if it's empty after a confext has been removed, the
         * child process can correctly undo the overlay in the target namespace, rather than attempting to
         * mount an empty overlay which the kernel does not allow, so this pruning has to be done here and
         * not later (nor earlier, as we don't know if an image is a confext until this point). */
        MountEntry **f, **t;
        for (f = entries, t = entries; f < entries + *n_entries; f++) {
                if (IN_SET((*f)->kind, MOUNT_EXTENSION_DIRECTORY, MOUNT_EXTENSION_IMAGE)) {
                        (*f)->filter_class = IMAGE_CONFEXT;

                        r = apply_one_mount("/", *f, p);
                        if (r < 0)
                                return r;
                        /* Nothing happened? Then it is not a confext, prune it from the lists */
                        if (r == 0) {
                                for (MountEntry **m = f; m < entries + *n_entries; m++) {
                                        if ((*m)->kind != MOUNT_OVERLAY)
                                                continue;

                                        _cleanup_strv_free_ char **pruned = NULL;

                                        STRV_FOREACH(ol, (*m)->overlay_layers)
                                                if (!path_startswith(*ol, (*f)->path)) {
                                                        r = strv_extend(&pruned, *ol);
                                                        if (r < 0)
                                                                return log_oom_debug();
                                                }
                                        strv_free((*m)->overlay_layers);
                                        (*m)->overlay_layers = TAKE_PTR(pruned);
                                }
                                mount_entry_free(set_remove(*s, *f));
                                continue;
                        }
                }

                *(t++) = *f;
        }

        *n_entries = t - entries;

        return 0;
}

int refresh_extensions_in_namespace(
                const PidRef *target,
                const char *hierarchy_env,
                const NamespaceParameters *p) {

        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF;
        _cleanup_set_free_ Set *entries = NULL;
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

        (void) dlopen_cryptsetup(LOG_DEBUG);

        r = parse_env_extension_hierarchies(&hierarchies, hierarchy_env);
        if (r < 0)
                return r;

        r = append_extensions(
                        &entries,
                        hierarchies,
                        p->extension_images,
                        p->n_extension_images,
                        p->extension_directories);
        if (r < 0)
                return r;

        r = mount_set_normalize(&entries);
        if (r < 0)
                return r;

        if (set_isempty(entries))
                return 0;

        _cleanup_free_ MountEntry **list = NULL;
        size_t n_list = 0;

        r = set_dump_sorted(entries, (void***) &list, &n_list);
        if (r < 0)
                return r;

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

                 (void) mkdir_p_label(STAGING_ROOT_DIR, 0555);

                r = refresh_apply_and_prune(p, &entries, list, &n_list);
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

                        r = refresh_grandchild_proc(target, list, n_list, pidns_fd, mntns_fd, root_fd, pair[1]);
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

                FOREACH_ARRAY(m, list, n_list) {
                        r = handle_mount_from_grandchild(*m, &fd_layers, &n_fd_layers, pair[0]);
                        if (r < 0)
                                _exit(EXIT_FAILURE);
                }

                r = pidref_wait_for_terminate_and_check("(sd-ns-refresh-exts-grandchild)", &grandchild, /* flags= */ 0);
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

char* bpf_delegate_to_string(uint64_t u, const char* (*parser)(uint64_t)) {
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

bool pinned_resource_is_host_root(PinnedResource *p) {
        int r;

        assert(p);

        /* Returns true if the service runs with our own root directory, i.e. if nothing is pinned
         * (no root configured), or if the pinned directory is the same directory (same inode on the
         * same device) as our own root. Meant to be called when the service is invoked, not when the
         * resource is pinned: the file descriptor of RootDirectoryFileDescriptor= is a detached
         * snapshot taken when it was received, which may refer to a tree that only becomes our own
         * root later, e.g. in the initrd before switching root. If we cannot check, assume a
         * separate root. The result is cached in .directory_fd_is_host_root, so that all calls
         * return the same answer, even if the check failed. */

        if (!pinned_resource_is_set(p))
                return true;

        if (p->directory_fd < 0)
                /* An image or mount stack, always a separate tree. */
                return false;

        if (p->directory_fd_is_host_root < 0) {
                /* AT_NO_AUTOMOUNT is passed to bypass the mount id comparison in inode_same_at(): a
                 * detached snapshot of our own root (like RootDirectoryFileDescriptor= provides)
                 * always has its own mount id, hence only the inode is compared. */
                r = inode_same_at(p->directory_fd, /* filea= */ NULL, AT_FDCWD, "/",
                                  AT_EMPTY_PATH|AT_NO_AUTOMOUNT);
                if (r < 0)
                        log_debug_errno(r, "Failed to check if the pinned root directory is identical to the host root directory, assuming it is not: %m");

                p->directory_fd_is_host_root = r > 0;
        }

        return p->directory_fd_is_host_root;
}
