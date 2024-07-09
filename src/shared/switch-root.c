/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base-filesystem.h"
#include "chase.h"
#include "creds-util.h"
#include "fd-util.h"
#include "initrd-util.h"
#include "log.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "switch-root.h"
#include "user-util.h"

int switch_root(const char *new_root,
                const char *old_root_after,   /* path below the new root, where to place the old root after the transition; may be NULL to unmount it */
                SwitchRootFlags flags) {

        /* Stuff mounted below /run/ we don't save on soft reboot, as it might have lost its relevance,
         * e.g. removable media and such. We rather want that the new boot mounts this fresh. But on
         * the switch from initrd we do use MS_REC, as it is expected that mounts set up in /run/ are
         * maintained. */
        static const struct {
                const char *path;
                unsigned long mount_flags;                 /* Flags to apply if SWITCH_ROOT_RECURSIVE_RUN is unset */
                unsigned long mount_flags_recursive_run;   /* Flags to apply if SWITCH_ROOT_RECURSIVE_RUN is set (0 if shall be skipped) */
        } transfer_table[] = {
                { "/dev",             MS_BIND|MS_REC,  MS_BIND|MS_REC }, /* Recursive, because we want to save the original /dev/shm/ + /dev/pts/ and similar */
                { "/sys",             MS_BIND|MS_REC,  MS_BIND|MS_REC }, /* Similar, we want to retain various API VFS, or the cgroupv1 /sys/fs/cgroup/ tree */
                { "/proc",            MS_BIND|MS_REC,  MS_BIND|MS_REC }, /* Similar */
                { "/run",             MS_BIND,         MS_BIND|MS_REC }, /* Recursive except on soft reboot, see above */
                { "/run/credentials", MS_BIND|MS_REC,  0 /* skip! */  }, /* Credential mounts should survive */
                { "/run/host",        MS_BIND|MS_REC,  0 /* skip! */  }, /* Host supplied hierarchy should also survive */
        };

        _cleanup_close_ int old_root_fd = -EBADF, new_root_fd = -EBADF;
        _cleanup_free_ char *resolved_old_root_after = NULL;
        int r, istmp;

        assert(new_root);

        /* Check if we shall remove the contents of the old root */
        old_root_fd = open("/", O_DIRECTORY|O_CLOEXEC);
        if (old_root_fd < 0)
                return log_error_errno(errno, "Failed to open root directory: %m");

        new_root_fd = open(new_root, O_PATH|O_DIRECTORY|O_CLOEXEC);
        if (new_root_fd < 0)
                return log_error_errno(errno, "Failed to open target directory '%s': %m", new_root);

        r = fds_are_same_mount(old_root_fd, new_root_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if old and new root directory/mount are the same: %m");
        if (r > 0) {
                log_debug("Skipping switch root, as old and new root directories/mounts are the same.");
                return 0;
        }

        /* Make the new root directory a mount point if it isn't */
        r = fd_make_mount_point(new_root_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to make new root directory a mount point: %m");
        if (r > 0) {
                int fd;

                /* When the path was not a mount point, then we need to reopen the path, otherwise, it still
                 * points to the underlying directory. */

                fd = open(new_root, O_DIRECTORY|O_CLOEXEC);
                if (fd < 0)
                        return log_error_errno(errno, "Failed to reopen target directory '%s': %m", new_root);

                close_and_replace(new_root_fd, fd);
        }

        if (FLAGS_SET(flags, SWITCH_ROOT_DESTROY_OLD_ROOT)) {
                istmp = fd_is_temporary_fs(old_root_fd);
                if (istmp < 0)
                        return log_error_errno(istmp, "Failed to stat root directory: %m");
                if (istmp > 0)
                        log_debug("Root directory is on tmpfs, will do cleanup later.");
        } else
                istmp = -1; /* don't know */

        if (old_root_after) {
                /* Determine where we shall place the old root after the transition */
                r = chase(old_root_after, new_root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved_old_root_after, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve %s/%s: %m", new_root, old_root_after);
                if (r == 0) /* Doesn't exist yet. Let's create it */
                        (void) mkdir_p_label(resolved_old_root_after, 0755);
        }

        /* We are about to unmount various file systems with MNT_DETACH (either explicitly via umount() or
         * indirectly via pivot_root()), and thus do not synchronously wait for them to be fully sync'ed —
         * all while making them invisible/inaccessible in the file system tree for later code. That makes
         * sync'ing them then difficult. Let's hence issue a manual sync() here, so that we at least can
         * guarantee all file systems are an a good state before entering this state. */
        if (!FLAGS_SET(flags, SWITCH_ROOT_DONT_SYNC))
                sync();

        /* Work-around for kernel design: the kernel refuses MS_MOVE if any file systems are mounted
         * MS_SHARED. Hence remount them MS_PRIVATE here as a work-around.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=847418 */
        if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0)
                return log_error_errno(errno, "Failed to set \"/\" mount propagation to private: %m");

        /* Do not fail if base_filesystem_create() fails. Not all switch roots are like base_filesystem_create() wants
         * them to look like. They might even boot, if they are RO and don't have the FS layout. Just ignore the error
         * and switch_root() nevertheless. */
        (void) base_filesystem_create_fd(new_root_fd, new_root, UID_INVALID, GID_INVALID);

        FOREACH_ELEMENT(transfer, transfer_table) {
                _cleanup_free_ char *chased = NULL;
                unsigned long mount_flags;

                mount_flags = FLAGS_SET(flags, SWITCH_ROOT_RECURSIVE_RUN) ? transfer->mount_flags_recursive_run : transfer->mount_flags;
                if (mount_flags == 0) /* skip if zero */
                        continue;

                if (access(transfer->path, F_OK) < 0) {
                        log_debug_errno(errno, "Path '%s' to move to target root directory, not found, ignoring: %m", transfer->path);
                        continue;
                }

                r = chase(transfer->path, new_root, CHASE_PREFIX_ROOT, &chased, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve %s/%s: %m", new_root, transfer->path);

                /* Let's see if it is a mount point already. */
                r = path_is_mount_point(chased);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine whether %s is a mount point: %m", chased);
                if (r > 0) /* If it is already mounted, then do nothing */
                        continue;

                r = mount_nofollow_verbose(LOG_ERR, transfer->path, chased, NULL, mount_flags, NULL);
                if (r < 0)
                        return r;
        }

        if (fchdir(new_root_fd) < 0)
                return log_error_errno(errno, "Failed to change directory to %s: %m", new_root);

        /* We first try a pivot_root() so that we can umount the old root dir. In many cases (i.e. where rootfs is /),
         * that's not possible however, and hence we simply overmount root */
        if (resolved_old_root_after)
                r = RET_NERRNO(pivot_root(".", resolved_old_root_after));
        else {
                r = RET_NERRNO(pivot_root(".", "."));
                if (r >= 0) {
                        /* Now unmount the upper of the two stacked file systems */
                        if (umount2(".", MNT_DETACH) < 0)
                                return log_error_errno(errno, "Failed to unmount the old root: %m");
                }
        }
        if (r < 0) {
                log_debug_errno(r, "Pivoting root file system failed, moving mounts instead: %m");

                if (resolved_old_root_after) {
                        r = mount_nofollow_verbose(LOG_ERR, "/", resolved_old_root_after, NULL, MS_BIND|MS_REC, NULL);
                        if (r < 0)
                                return r;
                }

                /* If we have to use MS_MOVE let's first try to get rid of *all* mounts we can, with the
                 * exception of the path we want to switch to, plus everything leading to it and within
                 * it. This is necessary because unlike pivot_root() just moving the mount to the root via
                 * MS_MOVE won't magically unmount anything below it. Once the chroot() succeeds the mounts
                 * below would still be around but invisible to us, because not accessible via
                 * /proc/self/mountinfo. Hence, let's clean everything up first, as long as we still can. */
                (void) umount_recursive_full(NULL, MNT_DETACH, STRV_MAKE(new_root));

                if (mount(".", "/", NULL, MS_MOVE, NULL) < 0)
                        return log_error_errno(errno, "Failed to move %s to /: %m", new_root);

                if (chroot(".") < 0)
                        return log_error_errno(errno, "Failed to change root: %m");

                if (chdir(".") < 0)
                        return log_error_errno(errno, "Failed to change directory: %m");
        }

        if (istmp > 0) {
                struct stat rb;

                if (fstat(old_root_fd, &rb) < 0)
                        return log_error_errno(errno, "Failed to stat old root directory: %m");

                /* Note: the below won't operate on non-memory file systems (i.e. only on tmpfs, ramfs), and
                 * it will stop at mount boundaries */
                (void) rm_rf_children(TAKE_FD(old_root_fd), 0, &rb); /* takes possession of the dir fd, even on failure */
        }

        return 0;
}
