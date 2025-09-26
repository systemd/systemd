/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mount.h>
#include <unistd.h>

#include "alloc-util.h"
#include "conf-files.h"
#include "dev-setup.h"
#include "efivars.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "label-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "smack-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "virt.h"

typedef enum MountMode {
        MNT_NONE              = 0,
        MNT_FATAL             = 1 << 0,
        MNT_IN_CONTAINER      = 1 << 1,
        MNT_CHECK_WRITABLE    = 1 << 2,
        MNT_FOLLOW_SYMLINK    = 1 << 3,
        MNT_USRQUOTA_GRACEFUL = 1 << 4,
} MountMode;

typedef struct MountPoint {
        const char *what;
        const char *where;
        const char *type;
        const char *options;
        unsigned long flags;
        MountMode mode;
        bool (*condition_fn)(void);
} MountPoint;

int mount_cgroupfs(const char *path) {
        assert(path);

        /* Mount a separate cgroupfs instance, taking all options we initial set into account. This is
         * especially useful when cgroup namespace is *not* employed, since the kernel overrides all
         * previous options if a new mount is established in initial cgns (c.f.
         * https://github.com/torvalds/linux/blob/b69bb476dee99d564d65d418e9a20acca6f32c3f/kernel/cgroup/cgroup.c#L1984)
         *
         * The options shall be kept in sync with those in mount_table below. */

        return mount_nofollow_verbose(LOG_ERR, "cgroup2", path, "cgroup2",
                                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
                                      "nsdelegate,memory_recursiveprot");
}

static const MountPoint mount_table[] = {
        { "proc",        "/proc",                     "proc",       NULL,                                       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_FATAL|MNT_IN_CONTAINER|MNT_FOLLOW_SYMLINK },
        { "sysfs",       "/sys",                      "sysfs",      NULL,                                       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_FATAL|MNT_IN_CONTAINER },
        { "devtmpfs",    "/dev",                      "devtmpfs",   "mode=0755" TMPFS_LIMITS_DEV,               MS_NOSUID|MS_STRICTATIME,
          MNT_FATAL|MNT_IN_CONTAINER },
        { "securityfs",  "/sys/kernel/security",      "securityfs", NULL,                                       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_NONE                   },
#if ENABLE_SMACK
        { "smackfs",     "/sys/fs/smackfs",           "smackfs",    "smackfsdef=*",                             MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_FATAL, mac_smack_use   },
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=01777,smackfsroot=*",                 MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          MNT_FATAL|MNT_USRQUOTA_GRACEFUL, mac_smack_use },
#endif
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=01777",                               MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          MNT_FATAL|MNT_IN_CONTAINER|MNT_USRQUOTA_GRACEFUL },
        { "devpts",      "/dev/pts",                  "devpts",     "mode=" STRINGIFY(TTY_MODE) ",gid=" STRINGIFY(TTY_GID), MS_NOSUID|MS_NOEXEC,
          MNT_IN_CONTAINER           },
#if ENABLE_SMACK
        { "tmpfs",       "/run",                      "tmpfs",      "mode=0755,smackfsroot=*" TMPFS_LIMITS_RUN, MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          MNT_FATAL, mac_smack_use   },
#endif
        { "tmpfs",       "/run",                      "tmpfs",      "mode=0755" TMPFS_LIMITS_RUN,               MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          MNT_FATAL|MNT_IN_CONTAINER },
        { "cgroup2",     "/sys/fs/cgroup",            "cgroup2",    "nsdelegate,memory_recursiveprot",          MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_FATAL|MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
#if ENABLE_PSTORE
        { "pstore",      "/sys/fs/pstore",            "pstore",     NULL,                                       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_NONE                   },
#endif
#if ENABLE_EFI
        { "efivarfs",    "/sys/firmware/efi/efivars", "efivarfs",   NULL,                                       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_NONE, is_efi_boot      },
#endif
        { "bpf",         "/sys/fs/bpf",               "bpf",        "mode=0700",                                MS_NOSUID|MS_NOEXEC|MS_NODEV,
          MNT_NONE                   },
};

/* The first three entries we might need before SELinux is up. The
 * fourth (securityfs) is needed by IMA to load a custom policy. The
 * other ones we can delay until SELinux and IMA are loaded. When
 * SMACK is enabled we need smackfs, too, so it's a fifth one. */
#if ENABLE_SMACK
#define N_EARLY_MOUNT 5
#else
#define N_EARLY_MOUNT 4
#endif

assert_cc(N_EARLY_MOUNT <= ELEMENTSOF(mount_table));

bool mount_point_is_api(const char *path) {
        /* Checks if this mount point is considered "API", and hence
         * should be ignored */

        FOREACH_ELEMENT(i, mount_table)
                if (path_equal(path, i->where))
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
        assert(p->what);
        assert(p->where);
        assert(p->type);

        priority = FLAGS_SET(p->mode, MNT_FATAL) ? LOG_ERR : LOG_DEBUG;

        if (p->condition_fn && !p->condition_fn())
                return 0;

        /* Relabel first, just in case */
        if (relabel)
                (void) label_fix(p->where, LABEL_IGNORE_ENOENT|LABEL_IGNORE_EROFS);

        r = path_is_mount_point_full(p->where, /* root = */ NULL, AT_SYMLINK_FOLLOW);
        if (r < 0 && r != -ENOENT) {
                log_full_errno(priority, r, "Failed to determine whether %s is a mount point: %m", p->where);
                return FLAGS_SET(p->mode, MNT_FATAL) ? r : 0;
        }
        if (r > 0)
                return 0;

        if (!FLAGS_SET(p->mode, MNT_IN_CONTAINER) && detect_container() > 0)
                return 0;

        /* The access mode here doesn't really matter too much, since
         * the mounted file system will take precedence anyway. */
        if (relabel)
                (void) mkdir_p_label(p->where, 0755);
        else
                (void) mkdir_p(p->where, 0755);

        _cleanup_free_ char *extend_options = NULL;
        const char *o = p->options;
        if (FLAGS_SET(p->mode, MNT_USRQUOTA_GRACEFUL)) {
                r = mount_option_supported(p->type, "usrquota", /* value= */ NULL);
                if (r < 0)
                        log_full_errno(priority, r, "Unable to determine whether %s supports 'usrquota' mount option, assuming not: %m", p->type);
                else if (r == 0)
                        log_debug("Not enabling 'usrquota' on '%s' as kernel lacks support for it.", p->where);
                else {
                        if (!strextend_with_separator(&extend_options, ",", p->options ?: POINTER_MAX, "usrquota"))
                                return log_oom();

                        o = extend_options;
                }
        }

        r = mount_verbose_full(priority, p->what, p->where, p->type, p->flags, o, FLAGS_SET(p->mode, MNT_FOLLOW_SYMLINK));
        if (r < 0)
                return FLAGS_SET(p->mode, MNT_FATAL) ? r : 0;

        /* Relabel again, since we now mounted something fresh here */
        if (relabel)
                (void) label_fix(p->where, 0);

        if (FLAGS_SET(p->mode, MNT_CHECK_WRITABLE))
                if (access(p->where, W_OK) < 0) {
                        r = -errno;

                        (void) umount2(p->where, UMOUNT_NOFOLLOW);
                        (void) rmdir(p->where);

                        log_full_errno(priority, r, "Mount point '%s' not writable after mounting, undoing: %m", p->where);
                        return FLAGS_SET(p->mode, MNT_FATAL) ? r : 0;
                }

        return 1;
}

static int mount_points_setup(size_t n, bool loaded_policy) {
        int r = 0;

        assert(n <= ELEMENTSOF(mount_table));

        FOREACH_ARRAY(mp, mount_table, n)
                RET_GATHER(r, mount_one(mp, loaded_policy));

        return r;
}

int mount_setup_early(void) {
        /* Do a minimal mount of /proc and friends to enable the most basic stuff, such as SELinux */
        return mount_points_setup(N_EARLY_MOUNT, /* loaded_policy= */ false);
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
                /* /run/initramfs/ + /run/nextroot/ are static data and big, no need to dynamically relabel
                 * its contents at boot... */
                if (PATH_STARTSWITH_SET(path, "/run/initramfs", "/run/nextroot"))
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

                n_extra = relabel_extra();

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabeled /dev/, /dev/shm/, /run/%s in %s.",
                         n_extra > 0 ? ", and additional files" : "",
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

        /* Make sure there's always a place where sandboxed environments can mount root file systems they are
         * about to move into, even when unprivileged, without having to create a temporary one in /tmp/
         * (which they then have to keep track of and clean) */
        (void) mkdir_label("/run/systemd/mount-rootfs", 0555);

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
