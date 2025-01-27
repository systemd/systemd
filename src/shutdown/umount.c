/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2010 ProFUSION embedded systems
***/

#include <errno.h>
#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "libmount-util.h"
#include "mkdir.h"
#include "mount-setup.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "umount.h"
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

int mount_points_list_get(FILE *f, MountPoint **head) {
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r;

        assert(head);

        r = libmount_parse_mountinfo(f, &table, &iter);
        if (r < 0)
                return log_error_errno(r, "Failed to parse /proc/self/mountinfo: %m");

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
                        return log_error_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

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
                    path_below_api_vfs(path))
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

                r = libmount_is_leaf(table, fs);
                if (r < 0)
                        return log_error_errno(r, "Failed to get children mounts for %s from /proc/self/mountinfo: %m", path);
                bool leaf = r;

                *m = (MountPoint) {
                        .remount_options = remount_options,
                        .remount_flags = remount_flags,
                        .try_remount_ro = try_remount_ro,

                        /* Unmount sysfs/procfs/… lazily, since syncing doesn't matter there, and it's OK if
                         * something keeps an fd open to it. */
                        .umount_lazily = is_api_vfs,
                        .leaf = leaf,
                };

                m->path = strdup(path);
                if (!m->path)
                        return log_oom();

                TAKE_PTR(remount_options);

                LIST_PREPEND(mount_point, *head, TAKE_PTR(m));
        }

        return 0;
}

static bool nonunmountable_path(const char *path) {
        assert(path);

        return PATH_IN_SET(path, "/", "/usr") ||
                path_startswith(path, "/run/initramfs");
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
                r = pid_get_comm(pid, &comm);
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
        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        _cleanup_(sigkill_nowaitp) pid_t pid = 0;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        r = pipe2(pfd, O_CLOEXEC|O_NONBLOCK);
        if (r < 0)
                return r;

        /* Due to the possibility of a remount operation hanging, we fork a child process and set a
         * timeout. If the timeout lapses, the assumption is that the particular remount failed. */
        r = safe_fork_full("(sd-remount)",
                           NULL,
                           pfd, ELEMENTSOF(pfd),
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                pfd[0] = safe_close(pfd[0]);

                log_info("Remounting '%s' read-only with options '%s'.", m->path, strempty(m->remount_options));

                /* Start the mount operation here in the child */
                r = mount(NULL, m->path, NULL, m->remount_flags, m->remount_options);
                if (r < 0)
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO,
                                       errno,
                                       "Failed to remount '%s' read-only: %m",
                                       m->path);

                report_errno_and_exit(pfd[1], r);
        }

        pfd[1] = safe_close(pfd[1]);

        r = wait_for_terminate_with_timeout(pid, DEFAULT_TIMEOUT_USEC);
        if (r == -ETIMEDOUT)
                log_error_errno(r, "Remounting '%s' timed out, issuing SIGKILL to PID " PID_FMT ".", m->path, pid);
        else if (r == -EPROTO) {
                /* Try to read error code from child */
                if (read(pfd[0], &r, sizeof(r)) == sizeof(r))
                        log_debug_errno(r, "Remounting '%s' failed abnormally, child process " PID_FMT " failed: %m", m->path, pid);
                else
                        r = log_debug_errno(EPROTO, "Remounting '%s' failed abnormally, child process " PID_FMT " aborted or exited non-zero.", m->path, pid);
                TAKE_PID(pid); /* child exited (just not as we expected) hence don't kill anymore */
        } else if (r < 0)
                log_error_errno(r, "Remounting '%s' failed unexpectedly, couldn't wait for child process " PID_FMT ": %m", m->path, pid);

        return r;
}

static int umount_with_timeout(MountPoint *m, bool last_try) {
        _cleanup_close_pair_ int pfd[2] = EBADF_PAIR;
        _cleanup_(sigkill_nowaitp) pid_t pid = 0;
        int r;

        BLOCK_SIGNALS(SIGCHLD);

        assert(m);

        r = pipe2(pfd, O_CLOEXEC|O_NONBLOCK);
        if (r < 0)
                return r;

        /* Due to the possibility of a umount operation hanging, we fork a child process and set a
         * timeout. If the timeout lapses, the assumption is that the particular umount failed. */
        r = safe_fork_full("(sd-umount)",
                           NULL,
                           pfd, ELEMENTSOF(pfd),
                           FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_REOPEN_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                pfd[0] = safe_close(pfd[0]);

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

                report_errno_and_exit(pfd[1], r);
        }

        pfd[1] = safe_close(pfd[1]);

        r = wait_for_terminate_with_timeout(pid, DEFAULT_TIMEOUT_USEC);
        if (r == -ETIMEDOUT)
                log_error_errno(r, "Unmounting '%s' timed out, issuing SIGKILL to PID " PID_FMT ".", m->path, pid);
        else if (r == -EPROTO) {
                /* Try to read error code from child */
                if (read(pfd[0], &r, sizeof(r)) == sizeof(r))
                        log_debug_errno(r, "Unmounting '%s' failed abnormally, child process " PID_FMT " failed: %m", m->path, pid);
                else
                        r = log_debug_errno(EPROTO, "Unmounting '%s' failed abnormally, child process " PID_FMT " aborted or exited non-zero.", m->path, pid);
                TAKE_PID(pid); /* It died, but abnormally, no purpose in killing */
        } else if (r < 0)
                log_error_errno(r, "Unmounting '%s' failed unexpectedly, couldn't wait for child process " PID_FMT ": %m", m->path, pid);

        return r;
}

/* This includes remounting readonly, which changes the kernel mount options.  Therefore the list passed to
 * this function is invalidated, and should not be reused. */
static int mount_points_list_umount(MountPoint **head, bool *changed, bool last_try) {
        int n_failed = 0, r;
        _cleanup_free_ char *resolved_mounts_path = NULL;

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
                r = umount_with_timeout(m, last_try);
                if (r < 0)
                        n_failed++;
                else
                        *changed = true;

                /* If a mount is busy, we move it to not keep parent mount points busy.
                 * If a mount point is not a leaf, moving it would invalidate our mount table.
                 * More moving will occur in next iteration with a fresh mount table.
                 */
                if (r != -EBUSY || !m->leaf)
                        continue;

                _cleanup_free_ char *dirname = NULL;

                r = path_extract_directory(m->path, &dirname);
                if (r < 0) {
                        n_failed++;
                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Cannot find directory for %s: %m", m->path);
                        continue;
                }

                /* We need to canonicalize /run/shutdown/mounts. We cannot compare inodes, since /run
                 * might be bind mounted somewhere we want to unmount. And we need to move all mounts in
                 * /run/shutdown/mounts from there.
                 */
                if (!resolved_mounts_path)
                        (void) chase("/run/shutdown/mounts", NULL, 0, &resolved_mounts_path, NULL);
                if (!path_equal(dirname, resolved_mounts_path)) {
                        char newpath[STRLEN("/run/shutdown/mounts/") + 16 + 1];

                        xsprintf(newpath, "/run/shutdown/mounts/%016" PRIx64, random_u64());

                        /* on error of is_dir, assume directory */
                        if (is_dir(m->path, true) != 0) {
                                r = mkdir_p(newpath, 0000);
                                if (r < 0) {
                                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not create directory %s: %m", newpath);
                                        continue;
                                }
                        } else {
                                r = touch_file(newpath, /* parents= */ true, USEC_INFINITY, UID_INVALID, GID_INVALID, 0700);
                                if (r < 0) {
                                        log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not create file %s: %m", newpath);
                                        continue;
                                }
                        }

                        log_info("Moving mount %s to %s.", m->path, newpath);

                        r = RET_NERRNO(mount(m->path, newpath, NULL, MS_MOVE, NULL));
                        if (r < 0) {
                                n_failed++;
                                log_full_errno(last_try ? LOG_ERR : LOG_INFO, r, "Could not move %s to %s: %m", m->path, newpath);
                        } else
                                *changed = true;
                }
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
