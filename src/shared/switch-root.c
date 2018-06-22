/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "base-filesystem.h"
#include "fd-util.h"
#include "fs-util.h"
#include "log.h"
#include "missing.h"
#include "mkdir.h"
#include "mount-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "switch-root.h"
#include "user-util.h"
#include "util.h"

int switch_root(const char *new_root,
                const char *old_root_after, /* path below the new root, where to place the old root after the transition */
                bool unmount_old_root,
                unsigned long mount_flags) {  /* MS_MOVE or MS_BIND */

        _cleanup_free_ char *resolved_old_root_after = NULL;
        _cleanup_close_ int old_root_fd = -1;
        bool old_root_remove;
        const char *i;
        int r;

        assert(new_root);
        assert(old_root_after);

        if (path_equal(new_root, "/"))
                return 0;

        /* Check if we shall remove the contents of the old root */
        old_root_remove = in_initrd();
        if (old_root_remove) {
                old_root_fd = open("/", O_RDONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY|O_DIRECTORY);
                if (old_root_fd < 0)
                        return log_error_errno(errno, "Failed to open root directory: %m");
        }

        /* Determine where we shall place the old root after the transition */
        r = chase_symlinks(old_root_after, new_root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &resolved_old_root_after);
        if (r < 0)
                return log_error_errno(r, "Failed to resolve %s/%s: %m", new_root, old_root_after);
        if (r == 0) /* Doesn't exist yet. Let's create it */
                (void) mkdir_p_label(resolved_old_root_after, 0755);

        /* Work-around for kernel design: the kernel refuses MS_MOVE if any file systems are mounted MS_SHARED. Hence
         * remount them MS_PRIVATE here as a work-around.
         *
         * https://bugzilla.redhat.com/show_bug.cgi?id=847418 */
        if (mount(NULL, "/", NULL, MS_REC|MS_PRIVATE, NULL) < 0)
                return log_error_errno(errno, "Failed to set \"/\" mount propagation to private: %m");

        FOREACH_STRING(i, "/sys", "/dev", "/run", "/proc") {
                _cleanup_free_ char *chased = NULL;

                r = chase_symlinks(i, new_root, CHASE_PREFIX_ROOT|CHASE_NONEXISTENT, &chased);
                if (r < 0)
                        return log_error_errno(r, "Failed to resolve %s/%s: %m", new_root, i);
                if (r > 0) {
                        /* Already exists. Let's see if it is a mount point already. */
                        r = path_is_mount_point(chased, NULL, 0);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine whether %s is a mount point: %m", chased);
                        if (r > 0) /* If it is already mounted, then do nothing */
                                continue;
                } else
                         /* Doesn't exist yet? */
                        (void) mkdir_p_label(chased, 0755);

                if (mount(i, chased, NULL, mount_flags, NULL) < 0)
                        return log_error_errno(r, "Failed to mount %s to %s: %m", i, chased);
        }

        /* Do not fail if base_filesystem_create() fails. Not all switch roots are like base_filesystem_create() wants
         * them to look like. They might even boot, if they are RO and don't have the FS layout. Just ignore the error
         * and switch_root() nevertheless. */
        (void) base_filesystem_create(new_root, UID_INVALID, GID_INVALID);

        if (chdir(new_root) < 0)
                return log_error_errno(errno, "Failed to change directory to %s: %m", new_root);

        /* We first try a pivot_root() so that we can umount the old root dir. In many cases (i.e. where rootfs is /),
         * that's not possible however, and hence we simply overmount root */
        if (pivot_root(new_root, resolved_old_root_after) >= 0) {

                /* Immediately get rid of the old root, if detach_oldroot is set.
                 * Since we are running off it we need to do this lazily. */
                if (unmount_old_root) {
                        r = umount_recursive(old_root_after, MNT_DETACH);
                        if (r < 0)
                                log_warning_errno(r, "Failed to unmount old root directory tree, ignoring: %m");
                }

        } else if (mount(new_root, "/", NULL, MS_MOVE, NULL) < 0)
                return log_error_errno(errno, "Failed to move %s to /: %m", new_root);

        if (chroot(".") < 0)
                return log_error_errno(errno, "Failed to change root: %m");

        if (chdir("/") < 0)
                return log_error_errno(errno, "Failed to change directory: %m");

        if (old_root_fd >= 0) {
                struct stat rb;

                if (fstat(old_root_fd, &rb) < 0)
                        log_warning_errno(errno, "Failed to stat old root directory, leaving: %m");
                else {
                        (void) rm_rf_children(old_root_fd, 0, &rb);
                        old_root_fd = -1;
                }
        }

        return 0;
}
