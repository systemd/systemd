/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "cgroup-setup.h"
#include "cgroup-util.h"
#include "conf-files.h"
#include "dev-setup.h"
#include "dirent-util.h"
#include "efi-loader.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "label.h"
#include "log.h"
#include "macro.h"
#include "mkdir-label.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "set.h"
#include "smack-util.h"
#include "strv.h"
#include "user-util.h"
#include "virt.h"

typedef enum MountMode {
        MNT_NONE           = 0,
        MNT_FATAL          = 1 << 0,
        MNT_IN_CONTAINER   = 1 << 1,
        MNT_CHECK_WRITABLE = 1 << 2,
        MNT_FOLLOW_SYMLINK = 1 << 3,
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
#if ENABLE_SMACK
#define N_EARLY_MOUNT 5
#else
#define N_EARLY_MOUNT 4
#endif

static const MountPoint mount_table[] = {
        { "proc",        "/proc",                     "proc",       NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER|MNT_FOLLOW_SYMLINK },
        { "sysfs",       "/sys",                      "sysfs",      NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devtmpfs",    "/dev",                      "devtmpfs",   "mode=755" TMPFS_LIMITS_DEV,               MS_NOSUID|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "securityfs",  "/sys/kernel/security",      "securityfs", NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#if ENABLE_SMACK
        { "smackfs",     "/sys/fs/smackfs",           "smackfs",    "smackfsdef=*",                            MS_NOSUID|MS_NOEXEC|MS_NODEV,
          mac_smack_use, MNT_FATAL                  },
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=1777,smackfsroot=*",                 MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          mac_smack_use, MNT_FATAL                  },
#endif
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=1777",                               MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devpts",      "/dev/pts",                  "devpts",     "mode=620,gid=" STRINGIFY(TTY_GID),        MS_NOSUID|MS_NOEXEC,
          NULL,          MNT_IN_CONTAINER           },
#if ENABLE_SMACK
        { "tmpfs",       "/run",                      "tmpfs",      "mode=755,smackfsroot=*" TMPFS_LIMITS_RUN, MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          mac_smack_use, MNT_FATAL                  },
#endif
        { "tmpfs",       "/run",                      "tmpfs",      "mode=755" TMPFS_LIMITS_RUN,               MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "cgroup2",     "/sys/fs/cgroup",            "cgroup2",    "nsdelegate,memory_recursiveprot",         MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_unified_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup2",     "/sys/fs/cgroup",            "cgroup2",    "nsdelegate",                              MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_unified_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup2",     "/sys/fs/cgroup",            "cgroup2",    NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_unified_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "tmpfs",       "/sys/fs/cgroup",            "tmpfs",      "mode=755" TMPFS_LIMITS_SYS_FS_CGROUP,     MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
          cg_is_legacy_wanted, MNT_FATAL|MNT_IN_CONTAINER },
        { "cgroup2",     "/sys/fs/cgroup/unified",    "cgroup2",    "nsdelegate",                              MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_hybrid_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup2",     "/sys/fs/cgroup/unified",    "cgroup2",    NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_hybrid_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup",      "/sys/fs/cgroup/systemd",    "cgroup",     "none,name=systemd,xattr",                 MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_legacy_wanted, MNT_IN_CONTAINER     },
        { "cgroup",      "/sys/fs/cgroup/systemd",    "cgroup",     "none,name=systemd",                       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_legacy_wanted, MNT_FATAL|MNT_IN_CONTAINER },
#if ENABLE_PSTORE
        { "pstore",      "/sys/fs/pstore",            "pstore",     NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#endif
#if ENABLE_EFI
        { "efivarfs",    "/sys/firmware/efi/efivars", "efivarfs",   NULL,                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          is_efi_boot,   MNT_NONE                   },
#endif
        { "bpf",         "/sys/fs/bpf",               "bpf",        "mode=700",                                MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE,                  },
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
        /* These are API file systems that might be mounted by other software, we just list them here so that
         * we know that we should ignore them. */
        FOREACH_STRING(i,
                       /* SELinux file systems */
                       "/sys/fs/selinux",
                       /* Container bind mounts */
                       "/dev/console",
                       "/proc/kmsg",
                       "/proc/sys",
                       "/proc/sys/kernel/random/boot_id")
                if (path_equal(path, i))
                        return true;

        if (path_startswith(path, "/run/host")) /* All mounts passed in from the container manager are
                                                 * something we better ignore. */
                return true;

        return false;
}

static int mount_one(const MountPoint *p, bool relabel) {
        int r, priority;

        assert(p);

        priority = (p->mode & MNT_FATAL) ? LOG_ERR : LOG_DEBUG;

        if (p->condition_fn && !p->condition_fn())
                return 0;

        /* Relabel first, just in case */
        if (relabel)
                (void) label_fix(p->where, LABEL_IGNORE_ENOENT|LABEL_IGNORE_EROFS);

        r = path_is_mount_point(p->where, NULL, AT_SYMLINK_FOLLOW);
        if (r < 0 && r != -ENOENT) {
                log_full_errno(priority, r, "Failed to determine whether %s is a mount point: %m", p->where);
                return (p->mode & MNT_FATAL) ? r : 0;
        }
        if (r > 0)
                return 0;

        /* Skip securityfs in a container */
        if (!(p->mode & MNT_IN_CONTAINER) && detect_container() > 0)
                return 0;

        /* The access mode here doesn't really matter too much, since
         * the mounted file system will take precedence anyway. */
        if (relabel)
                (void) mkdir_p_label(p->where, 0755);
        else
                (void) mkdir_p(p->where, 0755);

        log_debug("Mounting %s to %s of type %s with options %s.",
                  p->what,
                  p->where,
                  p->type,
                  strna(p->options));

        if (FLAGS_SET(p->mode, MNT_FOLLOW_SYMLINK))
                r = RET_NERRNO(mount(p->what, p->where, p->type, p->flags, p->options));
        else
                r = mount_nofollow(p->what, p->where, p->type, p->flags, p->options);
        if (r < 0) {
                log_full_errno(priority, r, "Failed to mount %s at %s: %m", p->type, p->where);
                return (p->mode & MNT_FATAL) ? r : 0;
        }

        /* Relabel again, since we now mounted something fresh here */
        if (relabel)
                (void) label_fix(p->where, 0);

        if (p->mode & MNT_CHECK_WRITABLE) {
                if (access(p->where, W_OK) < 0) {
                        r = -errno;

                        (void) umount2(p->where, UMOUNT_NOFOLLOW);
                        (void) rmdir(p->where);

                        log_full_errno(priority, r, "Mount point %s not writable after mounting: %m", p->where);
                        return (p->mode & MNT_FATAL) ? r : 0;
                }
        }

        return 1;
}

static int mount_points_setup(unsigned n, bool loaded_policy) {
        unsigned i;
        int r = 0;

        for (i = 0; i < n; i ++) {
                int j;

                j = mount_one(mount_table + i, loaded_policy);
                if (j != 0 && r >= 0)
                        r = j;
        }

        return r;
}

int mount_setup_early(void) {
        assert_cc(N_EARLY_MOUNT <= ELEMENTSOF(mount_table));

        /* Do a minimal mount of /proc and friends to enable the most
         * basic stuff, such as SELinux */
        return mount_points_setup(N_EARLY_MOUNT, false);
}

static const char *join_with(const char *controller) {

        static const char* const pairs[] = {
                "cpu", "cpuacct",
                "net_cls", "net_prio",
                NULL
        };

        assert(controller);

        /* This will lookup which controller to mount another controller with. Input is a controller name, and output
         * is the other controller name. The function works both ways: you can input one and get the other, and input
         * the other to get the one. */

        STRV_FOREACH_PAIR(x, y, pairs) {
                if (streq(controller, *x))
                        return *y;
                if (streq(controller, *y))
                        return *x;
        }

        return NULL;
}

static int symlink_controller(const char *target, const char *alias) {
        const char *a;
        int r;

        assert(target);
        assert(alias);

        a = strjoina("/sys/fs/cgroup/", alias);

        r = symlink_idempotent(target, a, false);
        if (r < 0)
                return log_error_errno(r, "Failed to create symlink %s: %m", a);

#if HAVE_SMACK_RUN_LABEL
        const char *p;

        p = strjoina("/sys/fs/cgroup/", target);

        r = mac_smack_copy(a, p);
        if (r < 0 && r != -EOPNOTSUPP)
                return log_error_errno(r, "Failed to copy smack label from %s to %s: %m", p, a);
#endif

        return 0;
}

int mount_cgroup_controllers(void) {
        _cleanup_set_free_ Set *controllers = NULL;
        int r;

        if (!cg_is_legacy_wanted())
                return 0;

        /* Mount all available cgroup controllers that are built into the kernel. */
        r = cg_kernel_controllers(&controllers);
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate cgroup controllers: %m");

        for (;;) {
                _cleanup_free_ char *options = NULL, *controller = NULL, *where = NULL;
                const char *other_controller;
                MountPoint p = {
                        .what = "cgroup",
                        .type = "cgroup",
                        .flags = MS_NOSUID|MS_NOEXEC|MS_NODEV,
                        .mode = MNT_IN_CONTAINER,
                };

                controller = set_steal_first(controllers);
                if (!controller)
                        break;

                /* Check if we shall mount this together with another controller */
                other_controller = join_with(controller);
                if (other_controller) {
                        _cleanup_free_ char *c = NULL;

                        /* Check if the other controller is actually available in the kernel too */
                        c = set_remove(controllers, other_controller);
                        if (c) {

                                /* Join the two controllers into one string, and maintain a stable ordering */
                                if (strcmp(controller, other_controller) < 0)
                                        options = strjoin(controller, ",", other_controller);
                                else
                                        options = strjoin(other_controller, ",", controller);
                                if (!options)
                                        return log_oom();
                        }
                }

                /* The simple case, where there's only one controller to mount together */
                if (!options)
                        options = TAKE_PTR(controller);

                where = path_join("/sys/fs/cgroup", options);
                if (!where)
                        return log_oom();

                p.where = where;
                p.options = options;

                r = mount_one(&p, true);
                if (r < 0)
                        return r;

                /* Create symlinks from the individual controller names, in case we have a joined mount */
                if (controller)
                        (void) symlink_controller(options, controller);
                if (other_controller)
                        (void) symlink_controller(options, other_controller);
        }

        /* Now that we mounted everything, let's make the tmpfs the cgroup file systems are mounted into read-only. */
        (void) mount_nofollow("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755" TMPFS_LIMITS_SYS_FS_CGROUP);

        return 0;
}

#if HAVE_SELINUX || ENABLE_SMACK
static int relabel_cb(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        switch (event) {

        case RECURSE_DIR_LEAVE:
        case RECURSE_DIR_SKIP_MOUNT:
                /* If we already saw this dirent when entering it or this is a dirent that on a different
                 * mount, don't relabel it. */
                return RECURSE_DIR_CONTINUE;

        case RECURSE_DIR_ENTER:
                /* /run/initramfs is static data and big, no need to dynamically relabel its contents at boot... */
                if (path_equal(path, "/run/initramfs"))
                        return RECURSE_DIR_SKIP_ENTRY;

                _fallthrough_;

        default:
                /* Otherwise, label it, even if we had trouble stat()ing it and similar. SELinux can figure this out */
                (void) label_fix(path, 0);
                return RECURSE_DIR_CONTINUE;
        }
}

static int relabel_tree(const char *path) {
        int r;

        r = recurse_dir_at(AT_FDCWD, path, 0, UINT_MAX, RECURSE_DIR_ENSURE_TYPE|RECURSE_DIR_SAME_MOUNT, relabel_cb, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to recursively relabel '%s': %m", path);

        return r;
}

static int relabel_cgroup_filesystems(void) {
        int r;
        struct statfs st;

        r = cg_all_unified();
        if (r == 0) {
                /* Temporarily remount the root cgroup filesystem to give it a proper label. Do this
                   only when the filesystem has been already populated by a previous instance of systemd
                   running from initrd. Otherwise don't remount anything and leave the filesystem read-write
                   for the cgroup filesystems to be mounted inside. */
                if (statfs("/sys/fs/cgroup", &st) < 0)
                        return log_error_errno(errno, "Failed to determine mount flags for /sys/fs/cgroup: %m");

                if (st.f_flags & ST_RDONLY)
                        (void) mount_nofollow(NULL, "/sys/fs/cgroup", NULL, MS_REMOUNT, NULL);

                (void) label_fix("/sys/fs/cgroup", 0);
                (void) relabel_tree("/sys/fs/cgroup");

                if (st.f_flags & ST_RDONLY)
                        (void) mount_nofollow(NULL, "/sys/fs/cgroup", NULL, MS_REMOUNT|MS_RDONLY, NULL);

        } else if (r < 0)
                return log_error_errno(r, "Failed to determine whether we are in all unified mode: %m");

        return 0;
}

static int relabel_extra(void) {
        _cleanup_strv_free_ char **files = NULL;
        int r, c = 0;

        /* Support for relabelling additional files or directories after loading the policy. For this, code in the
         * initrd simply has to drop in *.relabel files into /run/systemd/relabel-extra.d/. We'll read all such files
         * expecting one absolute path by line and will relabel each (and everyone below that in case the path refers
         * to a directory). These drop-in files are supposed to be absolutely minimal, and do not understand comments
         * and such. After the operation succeeded the files are removed, and the drop-in directory as well, if
         * possible.
         */

        r = conf_files_list(&files, ".relabel", NULL,
                            CONF_FILES_FILTER_MASKED | CONF_FILES_REGULAR,
                            "/run/systemd/relabel-extra.d/");
        if (r < 0)
                return log_error_errno(r, "Failed to enumerate /run/systemd/relabel-extra.d/, ignoring: %m");

        STRV_FOREACH(file, files) {
                _cleanup_fclose_ FILE *f = NULL;

                f = fopen(*file, "re");
                if (!f) {
                        log_warning_errno(errno, "Failed to open %s, ignoring: %m", *file);
                        continue;
                }

                for (;;) {
                        _cleanup_free_ char *line = NULL;

                        r = read_line(f, LONG_LINE_MAX, &line);
                        if (r < 0) {
                                log_warning_errno(r, "Failed to read %s, ignoring: %m", *file);
                                break;
                        }
                        if (r == 0) /* EOF */
                                break;

                        path_simplify(line);

                        if (!path_is_normalized(line)) {
                                log_warning("Path to relabel is not normalized, ignoring: %s", line);
                                continue;
                        }

                        if (!path_is_absolute(line)) {
                                log_warning("Path to relabel is not absolute, ignoring: %s", line);
                                continue;
                        }

                        log_debug("Relabelling additional file/directory '%s'.", line);
                        (void) label_fix(line, 0);
                        (void) relabel_tree(line);
                        c++;
                }

                if (unlink(*file) < 0)
                        log_warning_errno(errno, "Failed to remove %s, ignoring: %m", *file);
        }

        /* Remove when we complete things. */
        if (rmdir("/run/systemd/relabel-extra.d") < 0 &&
            errno != ENOENT)
                log_warning_errno(errno, "Failed to remove /run/systemd/relabel-extra.d/ directory: %m");

        return c;
}
#endif

int mount_setup(bool loaded_policy, bool leave_propagation) {
        int r;

        r = mount_points_setup(ELEMENTSOF(mount_table), loaded_policy);
        if (r < 0)
                return r;

#if HAVE_SELINUX || ENABLE_SMACK
        /* Nodes in devtmpfs and /run need to be manually updated for
         * the appropriate labels, after mounting. The other virtual
         * API file systems like /sys and /proc do not need that, they
         * use the same label for all their files. */
        if (loaded_policy) {
                usec_t before_relabel, after_relabel;
                int n_extra;

                before_relabel = now(CLOCK_MONOTONIC);

                FOREACH_STRING(i, "/dev", "/dev/shm", "/run")
                        (void) relabel_tree(i);

                (void) relabel_cgroup_filesystems();

                n_extra = relabel_extra();

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabelled /dev, /dev/shm, /run, /sys/fs/cgroup%s in %s.",
                         n_extra > 0 ? ", additional files" : "",
                         FORMAT_TIMESPAN(after_relabel - before_relabel, 0));
        }
#endif

        /* Create a few default symlinks, which are normally created
         * by udevd, but some scripts might need them before we start
         * udevd. */
        dev_setup(NULL, UID_INVALID, GID_INVALID);

        /* Mark the root directory as shared in regards to mount propagation. The kernel defaults to "private", but we
         * think it makes more sense to have a default of "shared" so that nspawn and the container tools work out of
         * the box. If specific setups need other settings they can reset the propagation mode to private if
         * needed. Note that we set this only when we are invoked directly by the kernel. If we are invoked by a
         * container manager we assume the container manager knows what it is doing (for example, because it set up
         * some directories with different propagation modes). */
        if (detect_container() <= 0 && !leave_propagation)
                if (mount(NULL, "/", NULL, MS_REC|MS_SHARED, NULL) < 0)
                        log_warning_errno(errno, "Failed to set up the root directory for shared mount propagation: %m");

        /* Create a few directories we always want around, Note that sd_booted() checks for /run/systemd/system, so
         * this mkdir really needs to stay for good, otherwise software that copied sd-daemon.c into their sources will
         * misdetect systemd. */
        (void) mkdir_label("/run/systemd", 0755);
        (void) mkdir_label("/run/systemd/system", 0755);

        /* Make sure we have a mount point to hide in sandboxes */
        (void) mkdir_label("/run/credentials", 0755);

        /* Also create /run/systemd/inaccessible nodes, so that we always have something to mount
         * inaccessible nodes from. If we run in a container the host might have created these for us already
         * in /run/host/inaccessible/. Use those if we can, since that way we likely get access to block/char
         * device nodes that are inaccessible, and if userns is used to nodes that are on mounts owned by a
         * userns outside the container and thus nicely read-only and not remountable. */
        if (access("/run/host/inaccessible/", F_OK) < 0) {
                if (errno != ENOENT)
                        log_debug_errno(errno, "Failed to check if /run/host/inaccessible exists, ignoring: %m");

                (void) make_inaccessible_nodes("/run/systemd", UID_INVALID, GID_INVALID);
        } else
                (void) symlink("../host/inaccessible", "/run/systemd/inaccessible");

        return 0;
}
