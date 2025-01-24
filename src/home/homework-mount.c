/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/mount.h>
#if WANT_LINUX_FS_H
#include <linux/fs.h>
#endif

#include "alloc-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "glyph-util.h"
#include "home-util.h"
#include "homework-mount.h"
#include "homework.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mount-util.h"
#include "namespace-util.h"
#include "path-util.h"
#include "string-util.h"
#include "uid-classification.h"
#include "user-util.h"

static const char *mount_options_for_fstype(const char *fstype) {
        const char *e;
        char *n;

        assert(fstype);

        /* Allow overriding our built-in defaults with an environment variable */
        n = strjoina("SYSTEMD_HOME_MOUNT_OPTIONS_", fstype);
        e = getenv(ascii_strupper(n));
        if (e)
                return e;

        if (streq(fstype, "ext4"))
                return "noquota,user_xattr";
        if (streq(fstype, "xfs"))
                return "noquota";
        if (streq(fstype, "btrfs"))
                return "noacl,compress=zstd:1";
        return NULL;
}

int home_mount_node(
                const char *node,
                const char *fstype,
                bool discard,
                unsigned long flags,
                const char *extra_mount_options) {

        _cleanup_free_ char *joined = NULL;
        const char *default_options;
        int r;

        assert(node);
        assert(fstype);

        default_options = mount_options_for_fstype(fstype);
        if (default_options) {
                if (!strextend_with_separator(&joined, ",", default_options))
                        return log_oom();
        }

        if (!strextend_with_separator(&joined, ",", discard ? "discard" : "nodiscard"))
                return log_oom();

        if (extra_mount_options) {
                if (!strextend_with_separator(&joined, ",", extra_mount_options))
                        return log_oom();
        }

        r = mount_nofollow_verbose(LOG_ERR, node, HOME_RUNTIME_WORK_DIR, fstype, flags|MS_RELATIME, joined);
        if (r < 0)
                return r;

        log_info("Mounting file system completed.");
        return 0;
}

int home_unshare_and_mkdir(void) {
        int r;

        if (unshare(CLONE_NEWNS) < 0)
                return log_error_errno(errno, "Couldn't unshare file system namespace: %m");

        assert(path_startswith(HOME_RUNTIME_WORK_DIR, "/run"));

        r = mount_nofollow_verbose(LOG_ERR, "/run", "/run", NULL, MS_SLAVE|MS_REC, NULL); /* Mark /run as MS_SLAVE in our new namespace */
        if (r < 0)
                return r;

        (void) mkdir_p(HOME_RUNTIME_WORK_DIR, 0700);
        return 0;
}

int home_unshare_and_mount(
                const char *node,
                const char *fstype,
                bool discard,
                unsigned long flags,
                const char *extra_mount_options) {

        int r;

        assert(node);
        assert(fstype);

        r = home_unshare_and_mkdir();
        if (r < 0)
                return r;

        r = home_mount_node(node, fstype, discard, flags, extra_mount_options);
        if (r < 0)
                return r;

        r = mount_nofollow_verbose(LOG_ERR, NULL, HOME_RUNTIME_WORK_DIR, NULL, MS_PRIVATE, NULL);
        if (r < 0) {
                (void) umount_verbose(LOG_ERR, HOME_RUNTIME_WORK_DIR, UMOUNT_NOFOLLOW);
                return r;
        }

        return 0;
}

int home_move_mount(const char *mount_suffix, const char *target) {
        _cleanup_free_ char *subdir = NULL;
        const char *d;
        int r;

        assert(target);

        /* If 'mount_suffix' is set, then we'll mount a subdir of the source mount into the host. If it's
         * NULL we'll move the mount itself */
        if (mount_suffix) {
                subdir = path_join(HOME_RUNTIME_WORK_DIR, mount_suffix);
                if (!subdir)
                        return log_oom();

                d = subdir;
        } else
                d = HOME_RUNTIME_WORK_DIR;

        (void) mkdir_p(target, 0700);

        r = mount_nofollow_verbose(LOG_ERR, d, target, NULL, MS_BIND, NULL);
        if (r < 0)
                return r;

        r = umount_recursive(HOME_RUNTIME_WORK_DIR, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to unmount %s: %m", HOME_RUNTIME_WORK_DIR);

        log_info("Moving to final mount point %s completed.", target);
        return 0;
}

static int append_identity_range(char **text, uid_t start, uid_t next_start, uid_t exclude) {
        /* Creates an identity range ranging from 'start' to 'next_start-1'. Excludes the UID specified by 'exclude' if
         * it is in that range. */

        assert(text);

        if (next_start <= start) /* Empty range? */
                return 0;

        if (exclude < start || exclude >= next_start) /* UID to exclude it outside of the range? */
                return strextendf(text, UID_FMT " " UID_FMT " " UID_FMT "\n", start, start, next_start - start);

        if (start == exclude && next_start == exclude + 1) /* The only UID in the range is the one to exclude? */
                return 0;

        if (exclude == start) /* UID to exclude at beginning of range? */
                return strextendf(text, UID_FMT " " UID_FMT " " UID_FMT "\n", start+1, start+1, next_start - start - 1);

        if (exclude == next_start - 1) /* UID to exclude at end of range? */
                return strextendf(text, UID_FMT " " UID_FMT " " UID_FMT "\n", start, start, next_start - start - 1);

        return strextendf(text,
                          UID_FMT " " UID_FMT " " UID_FMT "\n"
                          UID_FMT " " UID_FMT " " UID_FMT "\n",
                          start, start, exclude - start,
                          exclude + 1, exclude + 1, next_start - exclude - 1);
}

static int make_home_userns(uid_t stored_uid, uid_t exposed_uid) {
        _cleanup_free_ char *text = NULL;
        _cleanup_close_ int userns_fd = -EBADF;
        int r;

        assert(uid_is_valid(stored_uid));
        assert(uid_is_valid(exposed_uid));

        assert_cc(HOME_UID_MIN <= HOME_UID_MAX);
        assert_cc(HOME_UID_MAX < UID_NOBODY);

        /* Map everything below the homed UID range to itself (except for the UID we actually care about if
         * it is inside this range) */
        r = append_identity_range(&text, 0, HOME_UID_MIN, stored_uid);
        if (r < 0)
                return log_oom();

        /* Now map the UID we are doing this for to the target UID. */
        r = strextendf(&text, UID_FMT " " UID_FMT " " UID_FMT "\n", stored_uid, exposed_uid, 1u);
        if (r < 0)
                return log_oom();

        /* Map everything above the homed UID range to itself (again, excluding the UID we actually care
         * about if it is in that range). Also we leave "nobody" itself excluded) */
        r = append_identity_range(&text, HOME_UID_MAX, UID_NOBODY, stored_uid);
        if (r < 0)
                return log_oom();

        /* Also map the container range. People can use that to place containers owned by high UIDs in their
         * home directories if they really want. We won't manage this UID range for them but pass it through
         * 1:1, and it will lose its meaning once migrated between hosts. */
        r = append_identity_range(&text, CONTAINER_UID_MIN, CONTAINER_UID_MAX+1, stored_uid);
        if (r < 0)
                return log_oom();

        /* Map the foreign range 1:1. After all  what is foreign should remain foreign. */
        r = append_identity_range(&text, FOREIGN_UID_MIN, FOREIGN_UID_MAX+1, stored_uid);
        if (r < 0)
                return log_oom();

        /* Map nspawn's mapped root UID as identity mapping so that people can run nspawn uidmap mounted
         * containers off $HOME, if they want. */
        r = strextendf(&text, UID_FMT " " UID_FMT " " UID_FMT "\n", UID_MAPPED_ROOT, UID_MAPPED_ROOT, 1u);
        if (r < 0)
                return log_oom();

        /* Leave everything else unmapped, starting from UID_NOBODY itself. Specifically, this means the
         * whole space outside of 16-bit remains unmapped */

        log_debug("Creating userns with mapping:\n%s", text);

        userns_fd = userns_acquire(text, text); /* same uid + gid mapping */
        if (userns_fd < 0)
                return log_error_errno(userns_fd, "Failed to allocate user namespace: %m");

        return TAKE_FD(userns_fd);
}

int home_shift_uid(int dir_fd, const char *target, uid_t stored_uid, uid_t exposed_uid, int *ret_mount_fd) {
        _cleanup_close_ int mount_fd = -EBADF, userns_fd = -EBADF;
        int r;

        assert(dir_fd >= 0);
        assert(uid_is_valid(stored_uid));
        assert(uid_is_valid(exposed_uid));

        /* Let's try to set up a UID mapping for this directory. This is called when first creating a home
         * directory or when activating it again. We do this as optimization only, to avoid having to
         * recursively chown() things on each activation. If the kernel or file system doesn't support this
         * scheme we'll handle this gracefully, and not do anything, so that the later recursive chown()ing
         * then fixes up things for us. Note that the chown()ing is smart enough to skip things if they look
         * alright already.
         *
         * Note that this always creates a new mount (i.e. we use OPEN_TREE_CLONE), since applying idmaps is
         * not allowed once the mount is put in place. */

        mount_fd = open_tree(dir_fd, "", AT_EMPTY_PATH | OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        if (mount_fd < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno)) {
                        log_debug_errno(errno, "The open_tree() syscall is not supported, not setting up UID shift mount: %m");

                        if (ret_mount_fd)
                                *ret_mount_fd = -EBADF;

                        return 0;
                }

                return log_error_errno(errno, "Failed to open tree of home directory: %m");
        }

        userns_fd = make_home_userns(stored_uid, exposed_uid);
        if (userns_fd < 0)
                return userns_fd;

        /* Set the user namespace mapping attribute on the cloned mount point */
        if (mount_setattr(mount_fd, "", AT_EMPTY_PATH,
                          &(struct mount_attr) {
                                  .attr_set = MOUNT_ATTR_IDMAP,
                                  .userns_fd = userns_fd,
                          }, MOUNT_ATTR_SIZE_VER0) < 0) {

                if (ERRNO_IS_NOT_SUPPORTED(errno) || errno == EINVAL) { /* EINVAL is documented in mount_attr() as fs doesn't support idmapping */
                        log_debug_errno(errno, "UID/GID mapping for shifted mount not available, not setting it up: %m");

                        if (ret_mount_fd)
                                *ret_mount_fd = -EBADF;

                        return 0;
                }

                return log_error_errno(errno, "Failed to apply UID/GID mapping: %m");
        }

        if (target)
                r = move_mount(mount_fd, "", AT_FDCWD, target, MOVE_MOUNT_F_EMPTY_PATH);
        else
                r = move_mount(mount_fd, "", dir_fd, "", MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH);
        if (r < 0)
                return log_error_errno(errno, "Failed to apply UID/GID map: %m");

        log_debug("Applied uidmap mount to %s. Mapping is " UID_FMT " %s " UID_FMT ".",
                  strna(target), stored_uid, special_glyph(SPECIAL_GLYPH_ARROW_RIGHT), exposed_uid);

        if (ret_mount_fd)
                *ret_mount_fd = TAKE_FD(mount_fd);

        return 1;
}
