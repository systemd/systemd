/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <ftw.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "bus-util.h"
#include "cgroup-util.h"
#include "dev-setup.h"
#include "efivars.h"
#include "fileio.h"
#include "fs-util.h"
#include "label.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "path-util.h"
#include "set.h"
#include "smack-util.h"
#include "strv.h"
#include "user-util.h"
#include "util.h"
#include "virt.h"

typedef enum MountMode {
        MNT_NONE           = 0,
        MNT_FATAL          = 1 << 0,
        MNT_IN_CONTAINER   = 1 << 1,
        MNT_CHECK_WRITABLE = 1 << 2,
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
        { "sysfs",       "/sys",                      "sysfs",      NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "proc",        "/proc",                     "proc",       NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devtmpfs",    "/dev",                      "devtmpfs",   "mode=755",                MS_NOSUID|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "securityfs",  "/sys/kernel/security",      "securityfs", NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#if ENABLE_SMACK
        { "smackfs",     "/sys/fs/smackfs",           "smackfs",    "smackfsdef=*",            MS_NOSUID|MS_NOEXEC|MS_NODEV,
          mac_smack_use, MNT_FATAL                  },
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=1777,smackfsroot=*", MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          mac_smack_use, MNT_FATAL                  },
#endif
        { "tmpfs",       "/dev/shm",                  "tmpfs",      "mode=1777",               MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "devpts",      "/dev/pts",                  "devpts",     "mode=620,gid=" STRINGIFY(TTY_GID), MS_NOSUID|MS_NOEXEC,
          NULL,          MNT_IN_CONTAINER           },
#if ENABLE_SMACK
        { "tmpfs",       "/run",                      "tmpfs",      "mode=755,smackfsroot=*",  MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          mac_smack_use, MNT_FATAL                  },
#endif
        { "tmpfs",       "/run",                      "tmpfs",      "mode=755",                MS_NOSUID|MS_NODEV|MS_STRICTATIME,
          NULL,          MNT_FATAL|MNT_IN_CONTAINER },
        { "cgroup2",     "/sys/fs/cgroup",            "cgroup2",    "nsdelegate",              MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_unified_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup2",     "/sys/fs/cgroup",            "cgroup2",    NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_unified_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "tmpfs",       "/sys/fs/cgroup",            "tmpfs",      "mode=755",                MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME,
          cg_is_legacy_wanted, MNT_FATAL|MNT_IN_CONTAINER },
        { "cgroup2",     "/sys/fs/cgroup/unified",    "cgroup2",    "nsdelegate",              MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_hybrid_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup2",     "/sys/fs/cgroup/unified",    "cgroup2",    NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_hybrid_wanted, MNT_IN_CONTAINER|MNT_CHECK_WRITABLE },
        { "cgroup",      "/sys/fs/cgroup/systemd",    "cgroup",     "none,name=systemd,xattr", MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_legacy_wanted, MNT_IN_CONTAINER     },
        { "cgroup",      "/sys/fs/cgroup/systemd",    "cgroup",     "none,name=systemd",       MS_NOSUID|MS_NOEXEC|MS_NODEV,
          cg_is_legacy_wanted, MNT_FATAL|MNT_IN_CONTAINER },
        { "pstore",      "/sys/fs/pstore",            "pstore",     NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE                   },
#if ENABLE_EFI
        { "efivarfs",    "/sys/firmware/efi/efivars", "efivarfs",   NULL,                      MS_NOSUID|MS_NOEXEC|MS_NODEV,
          is_efi_boot,   MNT_NONE                   },
#endif
        { "bpf",         "/sys/fs/bpf",               "bpf",        "mode=700",                MS_NOSUID|MS_NOEXEC|MS_NODEV,
          NULL,          MNT_NONE,                  },
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

        if (mount(p->what,
                  p->where,
                  p->type,
                  p->flags,
                  p->options) < 0) {
                log_full_errno(priority, errno, "Failed to mount %s at %s: %m", p->type, p->where);
                return (p->mode & MNT_FATAL) ? -errno : 0;
        }

        /* Relabel again, since we now mounted something fresh here */
        if (relabel)
                (void) label_fix(p->where, 0);

        if (p->mode & MNT_CHECK_WRITABLE) {
                if (access(p->where, W_OK) < 0) {
                        r = -errno;

                        (void) umount(p->where);
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

int mount_cgroup_controllers(char ***join_controllers) {
        _cleanup_set_free_free_ Set *controllers = NULL;
        bool has_argument = !!join_controllers;
        int r;

        if (!cg_is_legacy_wanted())
                return 0;

        /* The defaults:
         * mount "cpu" + "cpuacct" together, and "net_cls" + "net_prio".
         *
         * We'd like to add "cpuset" to the mix, but "cpuset" doesn't really
         * work for groups with no initialized attributes.
         */
        char ***default_join_controllers = (char**[]) {
                STRV_MAKE("cpu", "cpuacct"),
                STRV_MAKE("net_cls", "net_prio"),
                NULL,
        };

        /* Mount all available cgroup controllers that are built into the kernel. */

        if (!has_argument)
                join_controllers = default_join_controllers;

        r = cg_kernel_controllers(&controllers);
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

                for (k = join_controllers; *k; k++)
                        if (strv_find(*k, controller))
                                break;

                if (*k) {
                        char **i, **j;

                        for (i = *k, j = *k; *i; i++) {

                                if (!streq(*i, controller)) {
                                        _cleanup_free_ char *t;

                                        t = set_remove(controllers, *i);
                                        if (!t) {
                                                if (has_argument)
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
                } else
                        options = TAKE_PTR(controller);

                where = strappend("/sys/fs/cgroup/", options);
                if (!where)
                        return log_oom();

                p.where = where;
                p.options = options;

                r = mount_one(&p, true);
                if (r < 0)
                        return r;

                if (r > 0 && *k) {
                        char **i;

                        for (i = *k; *i; i++) {
                                _cleanup_free_ char *t = NULL;

                                t = strappend("/sys/fs/cgroup/", *i);
                                if (!t)
                                        return log_oom();

                                r = symlink(options, t);
                                if (r >= 0) {
#ifdef SMACK_RUN_LABEL
                                        _cleanup_free_ char *src;
                                        src = strappend("/sys/fs/cgroup/", options);
                                        if (!src)
                                                return log_oom();
                                        r = mac_smack_copy(t, src);
                                        if (r < 0 && r != -EOPNOTSUPP)
                                                return log_error_errno(r, "Failed to copy smack label from %s to %s: %m", src, t);
#endif
                                } else if (errno != EEXIST)
                                        return log_error_errno(errno, "Failed to create symlink %s: %m", t);
                        }
                }
        }

        /* Now that we mounted everything, let's make the tmpfs the
         * cgroup file systems are mounted into read-only. */
        (void) mount("tmpfs", "/sys/fs/cgroup", "tmpfs", MS_REMOUNT|MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_STRICTATIME|MS_RDONLY, "mode=755");

        return 0;
}

#if HAVE_SELINUX || ENABLE_SMACK
static int nftw_cb(
                const char *fpath,
                const struct stat *sb,
                int tflag,
                struct FTW *ftwbuf) {

        /* No need to label /dev twice in a row... */
        if (_unlikely_(ftwbuf->level == 0))
                return FTW_CONTINUE;

        (void) label_fix(fpath, 0);

        /* /run/initramfs is static data and big, no need to
         * dynamically relabel its contents at boot... */
        if (_unlikely_(ftwbuf->level == 1 &&
                      tflag == FTW_D &&
                      streq(fpath, "/run/initramfs")))
                return FTW_SKIP_SUBTREE;

        return FTW_CONTINUE;
};

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
                        (void) mount(NULL, "/sys/fs/cgroup", NULL, MS_REMOUNT, NULL);

                (void) label_fix("/sys/fs/cgroup", 0);
                (void) nftw("/sys/fs/cgroup", nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);

                if (st.f_flags & ST_RDONLY)
                        (void) mount(NULL, "/sys/fs/cgroup", NULL, MS_REMOUNT|MS_RDONLY, NULL);

        } else if (r < 0)
                return log_error_errno(r, "Failed to determine whether we are in all unified mode: %m");

        return 0;
}
#endif

int mount_setup(bool loaded_policy) {
        int r = 0;

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
                char timespan[FORMAT_TIMESPAN_MAX];

                before_relabel = now(CLOCK_MONOTONIC);

                (void) nftw("/dev", nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);
                (void) nftw("/dev/shm", nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);
                (void) nftw("/run", nftw_cb, 64, FTW_MOUNT|FTW_PHYS|FTW_ACTIONRETVAL);

                r = relabel_cgroup_filesystems();
                if (r < 0)
                        return r;

                after_relabel = now(CLOCK_MONOTONIC);

                log_info("Relabelled /dev, /run and /sys/fs/cgroup in %s.",
                         format_timespan(timespan, sizeof(timespan), after_relabel - before_relabel, 0));
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
        if (detect_container() <= 0)
                if (mount(NULL, "/", NULL, MS_REC|MS_SHARED, NULL) < 0)
                        log_warning_errno(errno, "Failed to set up the root directory for shared mount propagation: %m");

        /* Create a few directories we always want around, Note that sd_booted() checks for /run/systemd/system, so
         * this mkdir really needs to stay for good, otherwise software that copied sd-daemon.c into their sources will
         * misdetect systemd. */
        (void) mkdir_label("/run/systemd", 0755);
        (void) mkdir_label("/run/systemd/system", 0755);

        /* Set up inaccessible (and empty) file nodes of all types */
        (void) mkdir_label("/run/systemd/inaccessible", 0000);
        (void) mknod("/run/systemd/inaccessible/reg", S_IFREG | 0000, 0);
        (void) mkdir_label("/run/systemd/inaccessible/dir", 0000);
        (void) mkfifo("/run/systemd/inaccessible/fifo", 0000);
        (void) mknod("/run/systemd/inaccessible/sock", S_IFSOCK | 0000, 0);

        /* The following two are likely to fail if we lack the privs for it (for example in an userns environment, if
         * CAP_SYS_MKNOD is missing, or if a device node policy prohibit major/minor of 0 device nodes to be
         * created). But that's entirely fine. Consumers of these files should carry fallback to use a different node
         * then, for example /run/systemd/inaccessible/sock, which is close enough in behaviour and semantics for most
         * uses. */
        (void) mknod("/run/systemd/inaccessible/chr", S_IFCHR | 0000, makedev(0, 0));
        (void) mknod("/run/systemd/inaccessible/blk", S_IFBLK | 0000, makedev(0, 0));

        return 0;
}
