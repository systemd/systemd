/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <errno.h>
#include <fcntl.h>
#include <linux/dm-ioctl.h>
#include <linux/major.h>
#include <linux/raid/md_u.h>
#include <linux/loop.h>
#include <sys/mount.h>
#include <sys/swap.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#if HAVE_VALGRIND_MEMCHECK_H
#include <valgrind/memcheck.h>
#endif

#include "sd-device.h"

#include "alloc-util.h"
#include "blockdev-util.h"
#include "def.h"
#include "device-util.h"
#include "dirent-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "libmount-util.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "sync-util.h"
#include "umount.h"
#include "util.h"
#include "virt.h"

static void mount_point_free(MountPoint **head, MountPoint *m) {
        assert(head);
        assert(m);

        LIST_REMOVE(mount_point, *head, m);

        free(m->path);
        free(m->remount_options);
        free(m);
}

void mount_points_list_free(MountPoint **head) {
        assert(head);

        while (*head)
                mount_point_free(head, *head);
}

int mount_points_list_get(const char *mountinfo, MountPoint **head) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        assert(head);

        r = libmount_parse(mountinfo, NULL, &table, &iter);
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s: %m", mountinfo ?: "/proc/self/mountinfo");

        for (;;) {
                _cleanup_free_ char *options = NULL, *remount_options = NULL;
                struct libmnt_fs *fs;
                const char *path, *fstype;
                unsigned long remount_flags = 0u;
                bool try_remount_ro, is_api_vfs;
                _cleanup_free_ MountPoint *m = NULL;

                r = mnt_table_next_fs(table, iter, &fs);
                if (r == 1) /* EOF */
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from %s: %m", mountinfo ?: "/proc/self/mountinfo");

                path = mnt_fs_get_target(fs);
                if (!path)
                        continue;

                fstype = mnt_fs_get_fstype(fs);

                /* Combine the generic VFS options with the FS-specific options. Duplicates are not a problem
                 * here, because the only options that should come up twice are typically ro/rw, which are
                 * turned into MS_RDONLY or the inversion of it.
                 *
                 * Even if there are duplicates later in mount_option_mangle() they shouldn't hurt anyways as
                 * they override each other. */
                if (!strextend_with_separator(&options, ",", mnt_fs_get_vfs_options(fs)))
                        return log_oom();
                if (!strextend_with_separator(&options, ",", mnt_fs_get_fs_options(fs)))
                        return log_oom();

                /* Ignore mount points we can't unmount because they are API or because we are keeping them
                 * open (like /dev/console). Also, ignore all mounts below API file systems, since they are
                 * likely virtual too, and hence not worth spending time on. Also, in unprivileged containers
                 * we might lack the rights to unmount these things, hence don't bother. */
                if (mount_point_is_api(path) ||
                    mount_point_ignore(path) ||
                    PATH_STARTSWITH_SET(path, "/dev", "/sys", "/proc"))
                        continue;

                is_api_vfs = fstype_is_api_vfs(fstype);

                /* If we are in a container, don't attempt to read-only mount anything as that brings no real
                 * benefits, but might confuse the host, as we remount the superblock here, not the bind
                 * mount.
                 *
                 * If the filesystem is a network fs, also skip the remount. It brings no value (we cannot
                 * leave a "dirty fs") and could hang if the network is down.  Note that umount2() is more
                 * careful and will not hang because of the network being down. */
                try_remount_ro = detect_container() <= 0 &&
                                 !fstype_is_network(fstype) &&
                                 !is_api_vfs &&
                                 !fstype_is_ro(fstype) &&
                                 !fstab_test_yes_no_option(options, "ro\0rw\0");

                if (try_remount_ro) {
                        /* mount(2) states that mount flags and options need to be exactly the same as they
                         * were when the filesystem was mounted, except for the desired changes. So we
                         * reconstruct both here and adjust them for the later remount call too. */

                        r = mnt_fs_get_propagation(fs, &remount_flags);
                        if (r < 0) {
                                log_warning_errno(r, "mnt_fs_get_propagation() failed for %s, ignoring: %m", path);
                                continue;
                        }

                        r = mount_option_mangle(options, remount_flags, &remount_flags, &remount_options);
                        if (r < 0) {
                                log_warning_errno(r, "mount_option_mangle failed for %s, ignoring: %m", path);
                                continue;
                        }

                        /* MS_BIND is special. If it is provided it will only make the mount-point
                         * read-only. If left out, the super block itself is remounted, which we want. */
                        remount_flags = (remount_flags|MS_REMOUNT|MS_RDONLY) & ~MS_BIND;
                }

                m = new(MountPoint, 1);
                if (!m)
                        return log_oom();

                *m = (MountPoint) {
                        .remount_options = remount_options,
                        .remount_flags = remount_flags,
                        .try_remount_ro = try_remount_ro,

                        /* Unmount sysfs/procfs/… lazily, since syncing doesn't matter there, and it's OK if
                         * something keeps an fd open to it. */
                        .umount_lazily = is_api_vfs,
                };

                m->path = strdup(path);
                if (!m->path)
                        return log_oom();

                TAKE_PTR(remount_options);

                LIST_PREPEND(mount_point, *head, TAKE_PTR(m));
        }

        return 0;
}

int swap_list_get(const char *swaps, MountPoint **head) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *t = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *i = NULL;
        int r;

        assert(head);

        t = mnt_new_table();
        i = mnt_new_iter(MNT_ITER_FORWARD);
        if (!t || !i)
                return log_oom();

        r = mnt_table_parse_swaps(t, swaps);
        if (r == -ENOENT) /* no /proc/swaps is fine */
                return 0;
        if (r < 0)
                return log_error_errno(r, "Failed to parse %s: %m", swaps ?: "/proc/swaps");

        for (;;) {
                struct libmnt_fs *fs;
                _cleanup_free_ MountPoint *swap = NULL;
                const char *source;

                r = mnt_table_next_fs(t, i, &fs);
                if (r == 1) /* EOF */
                        break;
                if (r < 0)
                        return log_error_errno(r, "Failed to get next entry from %s: %m", swaps ?: "/proc/swaps");

                source = mnt_fs_get_source(fs);
                if (!source)
                        continue;

                swap = new0(MountPoint, 1);
                if (!swap)
                        return log_oom();

                swap->path = strdup(source);
                if (!swap->path)
                        return log_oom();

                LIST_PREPEND(mount_point, *head, TAKE_PTR(swap));
        }

        return 0;
}

static int loopback_list_get(MountPoint **head) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        assert(head);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "block", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysname(e, "loop*");
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysattr(e, "loop/backing_file", NULL, true);
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char *p = NULL;
                const char *dn;
                MountPoint *lb;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
                        continue;

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                lb = new(MountPoint, 1);
                if (!lb)
                        return -ENOMEM;

                *lb = (MountPoint) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(mount_point, *head, lb);
        }

        return 0;
}

static int dm_list_get(MountPoint **head) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        assert(head);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "block", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysname(e, "dm-*");
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char *p = NULL;
                const char *dn;
                MountPoint *m;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
                        continue;

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                m = new(MountPoint, 1);
                if (!m)
                        return -ENOMEM;

                *m = (MountPoint) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(mount_point, *head, m);
        }

        return 0;
}

static int md_list_get(MountPoint **head) {
        _cleanup_(sd_device_enumerator_unrefp) sd_device_enumerator *e = NULL;
        sd_device *d;
        int r;

        assert(head);

        r = sd_device_enumerator_new(&e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_allow_uninitialized(e);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_subsystem(e, "block", true);
        if (r < 0)
                return r;

        r = sd_device_enumerator_add_match_sysname(e, "md*");
        if (r < 0)
                return r;

        /* Filter out partitions. */
        r = sd_device_enumerator_add_match_property(e, "DEVTYPE", "disk");
        if (r < 0)
                return r;

        FOREACH_DEVICE(e, d) {
                _cleanup_free_ char *p = NULL;
                const char *dn, *md_level;
                MountPoint *m;
                dev_t devnum;

                if (sd_device_get_devnum(d, &devnum) < 0 ||
                    sd_device_get_devname(d, &dn) < 0)
                        continue;

                r = sd_device_get_property_value(d, "MD_LEVEL", &md_level);
                if (r < 0) {
                        log_warning_errno(r, "Failed to get MD_LEVEL property for %s, ignoring: %m", dn);
                        continue;
                }

                /* MD "containers" are a special type of MD devices, used for external metadata.  Since it
                 * doesn't provide RAID functionality in itself we don't need to stop it. */
                if (streq(md_level, "container"))
                        continue;

                p = strdup(dn);
                if (!p)
                        return -ENOMEM;

                m = new(MountPoint, 1);
                if (!m)
                        return -ENOMEM;

                *m = (MountPoint) {
                        .path = TAKE_PTR(p),
                        .devnum = devnum,
                };

                LIST_PREPEND(mount_point, *head, m);
        }

        return 0;
}

static int delete_loopback(const char *device) {
        _cleanup_close_ int fd = -1;
        struct loop_info64 info;

        assert(device);

        fd = open(device, O_RDONLY|O_CLOEXEC);
        if (fd < 0) {
                log_debug_errno(errno, "Failed to open loopback device %s: %m", device);
                return errno == ENOENT ? 0 : -errno;
        }

        /* Loopback block devices don't sync in-flight blocks when we clear the fd, hence sync explicitly
         * first */
        if (fsync(fd) < 0)
                log_debug_errno(errno, "Failed to sync loop block device %s, ignoring: %m", device);

        if (ioctl(fd, LOOP_CLR_FD, 0) < 0) {
                if (errno == ENXIO) /* Nothing bound, didn't do anything */
                        return 0;

                if (errno != EBUSY)
                        return log_debug_errno(errno, "Failed to clear loopback device %s: %m", device);

                if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                        if (errno == ENXIO) /* What? Suddenly detached after all? That's fine by us then. */
                                return 1;

                        log_debug_errno(errno, "Failed to invoke LOOP_GET_STATUS64 on loopback device %s, ignoring: %m", device);
                        return -EBUSY; /* propagate original error */
                }

#if HAVE_VALGRIND_MEMCHECK_H
                VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

                if (FLAGS_SET(info.lo_flags, LO_FLAGS_AUTOCLEAR)) /* someone else already set LO_FLAGS_AUTOCLEAR for us? fine by us */
                        return -EBUSY; /* propagate original error */

                info.lo_flags |= LO_FLAGS_AUTOCLEAR;
                if (ioctl(fd, LOOP_SET_STATUS64, &info) < 0) {
                        if (errno == ENXIO) /* Suddenly detached after all? Fine by us */
                                return 1;

                        log_debug_errno(errno, "Failed to set LO_FLAGS_AUTOCLEAR flag for loop device %s, ignoring: %m", device);
                } else
                        log_debug("Successfully set LO_FLAGS_AUTOCLEAR flag for loop device %s.", device);

                return -EBUSY;
        }

        if (ioctl(fd, LOOP_GET_STATUS64, &info) < 0) {
                /* If the LOOP_CLR_FD above succeeded we'll see ENXIO here. */
                if (errno == ENXIO)
                        log_debug("Successfully detached loopback device %s.", device);
                else
                        log_debug_errno(errno, "Failed to invoke LOOP_GET_STATUS64 on loopback device %s, ignoring: %m", device); /* the LOOP_CLR_FD at least worked, let's hope for the best */

                return 1;
        }

#if HAVE_VALGRIND_MEMCHECK_H
        VALGRIND_MAKE_MEM_DEFINED(&info, sizeof(info));
#endif

        /* Linux makes LOOP_CLR_FD succeed whenever LO_FLAGS_AUTOCLEAR is set without actually doing
         * anything. Very confusing. Let's hence not claim we did anything in this case. */
        if (FLAGS_SET(info.lo_flags, LO_FLAGS_AUTOCLEAR))
                log_debug("Successfully called LOOP_CLR_FD on a loopback device %s with autoclear set, which is a NOP.", device);
        else
                log_debug("Weird, LOOP_CLR_FD succeeded but the device is still attached on %s.", device);

        return -EBUSY; /* Nothing changed, the device is still attached, hence it apparently is still busy */
}

static int delete_dm(MountPoint *m) {
        _cleanup_close_ int fd = -1;
        int r;

        assert(m);
        assert(major(m->devnum) != 0);
        assert(m->path);

        fd = open("/dev/mapper/control", O_RDWR|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        r = fsync_path_at(AT_FDCWD, m->path);
        if (r < 0)
                log_debug_errno(r, "Failed to sync DM block device %s, ignoring: %m", m->path);

        return RET_NERRNO(ioctl(fd, DM_DEV_REMOVE, &(struct dm_ioctl) {
                .version = {
                        DM_VERSION_MAJOR,
                        DM_VERSION_MINOR,
                        DM_VERSION_PATCHLEVEL
                },
                .data_size = sizeof(struct dm_ioctl),
                .dev = m->devnum,
        }));
}

static int delete_md(MountPoint *m) {
        _cleanup_close_ int fd = -1;

        assert(m);
        assert(major(m->devnum) != 0);
        assert(m->path);

        fd = open(m->path, O_RDONLY|O_CLOEXEC|O_EXCL);
        if (fd < 0)
                return -errno;

        if (fsync(fd) < 0)
                log_debug_errno(errno, "Failed to sync MD block device %s, ignoring: %m", m->path);

        return RET_NERRNO(ioctl(fd, STOP_ARRAY, NULL));
}

static bool nonunmountable_path(const char *path) {
        return path_equal(path, "/")
#if ! HAVE_SPLIT_USR
                || path_equal(path, "/usr")
#endif
                || path_startswith(path, "/run/initramfs");
}

static void log_umount_blockers(const char *mnt) {
        _cleanup_free_ char *blockers = NULL;
        int r;

        _cleanup_closedir_ DIR *dir = opendir("/proc");
        if (!dir)
                return (void) log_warning_errno(errno, "Failed to open /proc/: %m");

        FOREACH_DIRENT_ALL(de, dir, break) {
                if (!IN_SET(de->d_type, DT_DIR, DT_UNKNOWN))
                        continue;

                pid_t pid;
                if (parse_pid(de->d_name, &pid) < 0)
                        continue;

                _cleanup_free_ char *fdp = path_join(de->d_name, "fd");
                if (!fdp)
                        return (void) log_oom();

                _cleanup_closedir_ DIR *fd_dir = xopendirat(dirfd(dir), fdp, 0);
                if (!fd_dir) {
                        if (errno != ENOENT) /* process gone by now? */
                                log_debug_errno(errno, "Failed to open /proc/%s/, ignoring: %m",fdp);
                        continue;
                }

                bool culprit = false;
                FOREACH_DIRENT(fd_de, fd_dir, break) {
                        _cleanup_free_ char *open_file = NULL;

                        r = readlinkat_malloc(dirfd(fd_dir), fd_de->d_name, &open_file);
                        if (r < 0) {
                                if (r != -ENOENT) /* fd closed by now */
                                        log_debug_errno(r, "Failed to read link /proc/%s/%s, ignoring: %m", fdp, fd_de->d_name);
                                continue;
                        }

                        if (path_startswith(open_file, mnt)) {
                                culprit = true;
                                break;
                        }
                }

                if (!culprit)
                        continue;

                _cleanup_free_ char *comm = NULL;
                r = get_process_comm(pid, &comm);
                if (r < 0) {
                        if (r != -ESRCH) /* process gone by now */
                                log_debug_errno(r, "Failed to read process name of PID " PID_FMT ": %m", pid);
                        continue;
                }

                if (!strextend_with_separator(&blockers, ", ", comm))
                        return (void) log_oom();

                if (!strextend(&blockers, "(", de->d_name, ")"))
                        return (void) log_oom();
        }

        if (blockers)
                log_warning("Unmounting '%s' blocked by: %s", mnt, blockers);
}

static int remount_with_timeout(MountPoint *m, bool last_try) {
        pid_t pid;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        /* Due to the possibility of a remount operation hanging, we fork a child process and set a
         * timeout. If the timeout lapses, the assumption is that the particular remount failed. */
        r = safe_fork("(sd-remount)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("Remounting '%s' read-only with options '%s'.", m->path, strempty(m->remount_options));

                /* Start the mount operation here in the child */
                r = mount(NULL, m->path, NULL, m->remount_flags, m->remount_options);
                if (r < 0)
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO,
                                       errno,
                                       "Failed to remount '%s' read-only: %m",
                                       m->path);

                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        r = wait_for_terminate_with_timeout(pid, DEFAULT_TIMEOUT_USEC);
        if (r == -ETIMEDOUT) {
                log_error_errno(r, "Remounting '%s' timed out, issuing SIGKILL to PID " PID_FMT ".", m->path, pid);
                (void) kill(pid, SIGKILL);
        } else if (r == -EPROTO)
                log_debug_errno(r, "Remounting '%s' failed abnormally, child process " PID_FMT " aborted or exited non-zero.", m->path, pid);
        else if (r < 0)
                log_error_errno(r, "Remounting '%s' failed unexpectedly, couldn't wait for child process " PID_FMT ": %m", m->path, pid);

        return r;
}

static int umount_with_timeout(MountPoint *m, bool last_try) {
        pid_t pid;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        /* Due to the possibility of a umount operation hanging, we fork a child process and set a
         * timeout. If the timeout lapses, the assumption is that the particular umount failed. */
        r = safe_fork("(sd-umount)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                log_info("Unmounting '%s'.", m->path);

                /* Start the mount operation here in the child Using MNT_FORCE causes some filesystems
                 * (e.g. FUSE and NFS and other network filesystems) to abort any pending requests and return
                 * -EIO rather than blocking indefinitely. If the filesysten is "busy", this may allow
                 * processes to die, thus making the filesystem less busy so the unmount might succeed
                 * (rather than return EBUSY). */
                r = RET_NERRNO(umount2(m->path,
                                       UMOUNT_NOFOLLOW | /* Don't follow symlinks: this should never happen unless our mount list was wrong */
                                       (m->umount_lazily ? MNT_DETACH : MNT_FORCE)));
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Failed to unmount %s: %m", m->path);

                        if (r == -EBUSY && last_try)
                                log_umount_blockers(m->path);
                }

                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        r = wait_for_terminate_with_timeout(pid, DEFAULT_TIMEOUT_USEC);
        if (r == -ETIMEDOUT) {
                log_error_errno(r, "Unmounting '%s' timed out, issuing SIGKILL to PID " PID_FMT ".", m->path, pid);
                (void) kill(pid, SIGKILL);
        } else if (r == -EPROTO)
                log_debug_errno(r, "Unmounting '%s' failed abnormally, child process " PID_FMT " aborted or exited non-zero.", m->path, pid);
        else if (r < 0)
                log_error_errno(r, "Unmounting '%s' failed unexpectedly, couldn't wait for child process " PID_FMT ": %m", m->path, pid);

        return r;
}

/* This includes remounting readonly, which changes the kernel mount options.  Therefore the list passed to
 * this function is invalidated, and should not be reused. */
static int mount_points_list_umount(MountPoint **head, bool *changed, bool last_try) {
        int n_failed = 0;

        assert(head);
        assert(changed);

        LIST_FOREACH(mount_point, m, *head) {
                if (m->try_remount_ro) {
                        /* We always try to remount directories read-only first, before we go on and umount
                         * them.
                         *
                         * Mount points can be stacked. If a mount point is stacked below / or /usr, we
                         * cannot umount or remount it directly, since there is no way to refer to the
                         * underlying mount. There's nothing we can do about it for the general case, but we
                         * can do something about it if it is aliased somewhere else via a bind mount. If we
                         * explicitly remount the super block of that alias read-only we hence should be
                         * relatively safe regarding keeping a dirty fs we cannot otherwise see.
                         *
                         * Since the remount can hang in the instance of remote filesystems, we remount
                         * asynchronously and skip the subsequent umount if it fails. */
                        if (remount_with_timeout(m, last_try) < 0) {
                                /* Remount failed, but try unmounting anyway,
                                 * unless this is a mount point we want to skip. */
                                if (nonunmountable_path(m->path)) {
                                        n_failed++;
                                        continue;
                                }
                        }
                }

                /* Skip / and /usr since we cannot unmount that anyway, since we are running from it. They
                 * have already been remounted ro. */
                if (nonunmountable_path(m->path))
                        continue;

                /* Trying to umount */
                if (umount_with_timeout(m, last_try) < 0)
                        n_failed++;
                else
                        *changed = true;
        }

        return n_failed;
}

static int swap_points_list_off(MountPoint **head, bool *changed) {
        int n_failed = 0;

        assert(head);
        assert(changed);

        LIST_FOREACH(mount_point, m, *head) {
                log_info("Deactivating swap %s.", m->path);
                if (swapoff(m->path) < 0) {
                        log_warning_errno(errno, "Could not deactivate swap %s: %m", m->path);
                        n_failed++;
                        continue;
                }

                *changed = true;
                mount_point_free(head, m);
        }

        return n_failed;
}

static int loopback_points_list_detach(MountPoint **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device("/", &rootdev);

        LIST_FOREACH(mount_point, m, *head) {
                if (major(rootdev) != 0 && rootdev == m->devnum) {
                        n_failed++;
                        continue;
                }

                log_info("Detaching loopback %s.", m->path);
                r = delete_loopback(m->path);
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not detach loopback %s: %m", m->path);
                        n_failed++;
                        continue;
                }
                if (r > 0)
                        *changed = true;

                mount_point_free(head, m);
        }

        return n_failed;
}

static int dm_points_list_detach(MountPoint **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device("/", &rootdev);

        LIST_FOREACH(mount_point, m, *head) {
                if (major(rootdev) != 0 && rootdev == m->devnum) {
                        n_failed ++;
                        continue;
                }

                log_info("Detaching DM %s (%u:%u).", m->path, major(m->devnum), minor(m->devnum));
                r = delete_dm(m);
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not detach DM %s: %m", m->path);
                        n_failed++;
                        continue;
                }

                *changed = true;
                mount_point_free(head, m);
        }

        return n_failed;
}

static int md_points_list_detach(MountPoint **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        dev_t rootdev = 0;

        assert(head);
        assert(changed);

        (void) get_block_device("/", &rootdev);

        LIST_FOREACH(mount_point, m, *head) {
                if (major(rootdev) != 0 && rootdev == m->devnum) {
                        n_failed ++;
                        continue;
                }

                log_info("Stopping MD %s (%u:%u).", m->path, major(m->devnum), minor(m->devnum));
                r = delete_md(m);
                if (r < 0) {
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not stop MD %s: %m", m->path);
                        n_failed++;
                        continue;
                }

                *changed = true;
                mount_point_free(head, m);
        }

        return n_failed;
}

static int umount_all_once(bool *changed, bool last_try) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, mp_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(mp_list_head);
        r = mount_points_list_get(NULL, &mp_list_head);
        if (r < 0)
                return r;

        return mount_points_list_umount(&mp_list_head, changed, last_try);
}

int umount_all(bool *changed, bool last_try) {
        bool umount_changed;
        int r;

        assert(changed);

        /* Retry umount, until nothing can be umounted anymore. Mounts are processed in order, newest
         * first. The retries are needed when an old mount has been moved, to a path inside a newer mount. */
        do {
                umount_changed = false;

                r = umount_all_once(&umount_changed, last_try);
                if (umount_changed)
                        *changed = true;
        } while (umount_changed);

        return r;
}

int swapoff_all(bool *changed) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, swap_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(swap_list_head);

        r = swap_list_get(NULL, &swap_list_head);
        if (r < 0)
                return r;

        return swap_points_list_off(&swap_list_head, changed);
}

int loopback_detach_all(bool *changed, bool last_try) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, loopback_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(loopback_list_head);

        r = loopback_list_get(&loopback_list_head);
        if (r < 0)
                return r;

        return loopback_points_list_detach(&loopback_list_head, changed, last_try);
}

int dm_detach_all(bool *changed, bool last_try) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, dm_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(dm_list_head);

        r = dm_list_get(&dm_list_head);
        if (r < 0)
                return r;

        return dm_points_list_detach(&dm_list_head, changed, last_try);
}

int md_detach_all(bool *changed, bool last_try) {
        _cleanup_(mount_points_list_free) LIST_HEAD(MountPoint, md_list_head);
        int r;

        assert(changed);

        LIST_HEAD_INIT(md_list_head);

        r = md_list_get(&md_list_head);
        if (r < 0)
                return r;

        return md_points_list_detach(&md_list_head, changed, last_try);
}
