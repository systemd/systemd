/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "base-filesystem.h"
#include "chase.h"
#include "errno-util.h"
#include "fd-util.h"
#include "libmount-util.h"
#include "log.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "path-util.h"
#include "rm-rf.h"
#include "stat-util.h"
#include "string-util.h"
#include "switch-root.h"
#include "sync-util.h"

/* Flushes out the file systems that are about to become unreachable/"departing" as we switch to
 * 'new_root', so that they are in a good state before they possibly are detached with MNT_DETACH.
 * Explicitly excludes 'new_root' and any file systems mounted below it, since those remain mounted and
 * reachable after the transition, and will continue to be written to/synced normally as part of their
 * regular life cycle afterwards. This deliberately avoids a global sync() (which would also flush out any
 * other, completely unrelated file systems that happen to be mounted on the system, e.g. any additional
 * data partitions, network shares, removable media, …), since this code path is very much on the critical
 * path during boot (as part of initrd-switch-root.service) and soft-reboot.
 *
 * On any failure that means we can't be sure we've covered everything (libmount unavailable, or
 * /proc/self/mountinfo can't be parsed, in full or in part), returns a negative error and leaves it up to
 * the caller to fall back to a plain, global sync() instead, rather than doing that here itself: that way
 * the fallback logic lives in exactly one place. */
static int sync_departing_file_systems(const char *new_root) {
#if HAVE_LIBMOUNT
        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r, new_root_mnt_id;

        r = libmount_parse_mountinfo(/* source= */ NULL, &table, &iter);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        /* Determine new_root's own, definitely-current mount ID once upfront, so that below we can tell
         * apart the file system that is actually still going to be reachable at 'new_root' after the
         * switch (which we want to skip, see below) from any other, stale/shadowed mountinfo entry that
         * merely happens to share the exact same target path (which we do not want to skip, see below). */
        r = path_get_mnt_id(new_root, &new_root_mnt_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine current mount ID of '%s': %m", new_root);

        for (;;) {
                struct libmnt_fs *fs;
                const char *path, *fstype, *rest;

                r = sym_mnt_table_next_fs(table, iter, &fs);
                if (r == 1) /* EOF */
                        break;
                if (r < 0)
                        /* Something went wrong walking the remainder of the table. We can't tell which
                         * (if any) of the remaining file systems still need to be synced, so let the
                         * caller fall back to a global sync() to cover them (and everything we might have
                         * already processed again, that's harmless), rather than risk silently skipping
                         * something that matters. */
                        return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                path = sym_mnt_fs_get_target(fs);
                if (!path)
                        /* Same reasoning as above: we can't identify (let alone sync) this entry at all,
                         * so let the caller fall back to a global sync() rather than silently drop it. In
                         * practice this shouldn't happen for a real mountinfo entry. */
                        return log_debug_errno(SYNTHETIC_ERRNO(ENODATA), "Mount entry without a target path found, giving up.");

                rest = path_startswith(path, new_root);
                if (rest) {
                        /* Anything strictly below new_root remains mounted and reachable after the switch
                         * as part of its subtree, hence doesn't need to be synced out defensively here. */
                        if (!isempty(rest))
                                continue;

                        /* 'path' is new_root itself. If this entry's mount ID matches the one we
                         * determined new_root's current mount actually has, this is that same, still
                         * reachable file system: skip it exactly as with anything below it, to avoid
                         * needlessly syncing something that isn't going away. Otherwise, this entry must
                         * be a stale one that's now shadowed by the (different) file system actually
                         * mounted at new_root (e.g. if new_root wasn't already its own mount point and got
                         * bind-mounted onto itself earlier in switch_root()) and is about to become
                         * unreachable just the same: let it fall through to the general shadow/sync
                         * handling below instead of silently skipping it here too. */
                        if (sym_mnt_fs_get_id(fs) == new_root_mnt_id)
                                continue;
                }

                fstype = sym_mnt_fs_get_fstype(fs);
                if (fstype && fstype_is_api_vfs(fstype)) {
                        log_debug("Not synchronizing '%s': file system type '%s' is API VFS.",
                                  path, strna(fstype));
                        continue;
                }

                /* mountinfo may list the same target path more than once, if one mount shadows another
                 * (i.e. something else has since been mounted on top of it). Opening 'path' always
                 * resolves to whatever is currently visible there, i.e. the top-most mount, which might
                 * not be the (possibly departing) one this specific entry refers to. This uses the same
                 * check get_sub_mounts() already does for the same reason.
                 *
                 * If this entry is confirmed to be currently shadowed (r == 0), its own superblock isn't
                 * reachable by path at all any more, and if it's the one carrying dirty data that's about
                 * to become unreachable, that data would be silently dropped if we just skipped it here
                 * (unlike the blanket sync() we're replacing, which covers shadowed superblocks too, since
                 * it isn't path based).
                 *
                 * If we fail to determine this either way (r < 0), we also don't know what's currently at
                 * 'path' any more: plain syncfs_path() doesn't suppress automounts, so blindly opening
                 * 'path' here could trigger an untouched autofs mount point, or block on a stale network
                 * mount that has since been stacked on top - exactly what fstype_is_worth_syncing() above is
                 * trying to prevent us from doing.
                 *
                 * Rather than risk either of these, let the caller fall back to one global sync(): a
                 * global sync() trivially covers this (and every other) file system correctly, so there's
                 * nothing left to do here afterwards. This should be rare in practice (shadowed departing
                 * mounts, or failures determining this, are both unusual), so this doesn't meaningfully
                 * undercut the benefit of the targeted sync in the common case. */
                r = libmount_fs_id_matches_path(fs, path);
                if (r < 0)
                        return log_debug_errno(r, "Failed to determine whether '%s' is currently shadowed by another mount: %m", path);
                if (r == 0)
                        return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "'%s' is currently shadowed by another mount, giving up.", path);

                /* Note there's an inherent, unavoidable TOCTOU race between the check above and the
                 * open() syncfs_path() is about to do below: if something else mounts something new on
                 * top of 'path' in between (e.g. an autofs mount point gets triggered by an unrelated
                 * process, or a network mount appears), that open() could still end up triggering an
                 * automount, or blocking on that new, possibly stale, mount — the very thing the check
                 * above exists to prevent. Unlike a failed lookup (handled above) or a failed syncfs()
                 * (handled below), a *hanging* open() can't be recovered from by falling back to sync()
                 * afterwards, since we'd never get back here to do so. There is no way to open a real,
                 * syncfs()-capable file descriptor while also reliably suppressing automounts the way
                 * statx()'s AT_NO_AUTOMOUNT does for the check above (that flag has no open()/openat()
                 * equivalent), so this narrow window can't be fully closed without disproportionate
                 * effort (e.g. performing the open() in a separate, killable/timeout-bounded process).
                 * We accept it here: this code only runs with most other activity on the system already
                 * quiesced (during the switch_root() transition itself), so the window for something else
                 * to concurrently and adversarially remount 'path' in the first place is already narrow. */
                r = syncfs_path(AT_FDCWD, path);
                if (r < 0)
                        /* We can't tell here whether this failed because we couldn't even open 'path'
                         * (e.g. a transient error, or its state changed between the mount ID check above
                         * and this open()), in which case a global sync() would still cover it just fine,
                         * or because syncfs() itself hit a genuine, lower-level I/O error, in which case a
                         * global sync() would likely run into the very same error and not actually recover
                         * anything. Since we can't distinguish the two, and dropping this file system's
                         * writeback silently would violate our "never regress the safety of the sync() we
                         * replace" guarantee for the (plausibly more common) former case, let the caller
                         * fall back to a global sync() here too, same as for the other cases above. */
                        return log_debug_errno(r, "Failed to synchronize file system '%s': %m", path);
        }

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

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
                bool skip_recursive_run;                   /* Whether or not this path should be skipped when SWITCH_ROOT_RECURSIVE_RUN is set */
        } transfer_table[] = {
                { "/dev",             MS_BIND|MS_REC,  /* skip_recursive_run = */ false }, /* Recursive, because we want to save the original /dev/shm/ + /dev/pts/ and similar */
                { "/sys",             MS_BIND|MS_REC,  /* skip_recursive_run = */ false }, /* Similar, we want to retain various API VFS, or the cgroupv1 /sys/fs/cgroup/ tree */
                { "/proc",            MS_BIND|MS_REC,  /* skip_recursive_run = */ false }, /* Similar */
                { "/run",             MS_BIND,         /* skip_recursive_run = */ false }, /* Recursive except on soft reboot, see above */
                { "/run/credentials", MS_BIND|MS_REC,  /* skip_recursive_run = */ true  }, /* Credential mounts should survive */
                { "/run/host",        MS_BIND|MS_REC,  /* skip_recursive_run = */ true  }, /* Host supplied hierarchy should also survive */
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

        r = fds_inode_and_mount_same(old_root_fd, new_root_fd); /* checks if referenced inodes and mounts match */
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
         * sync'ing them then difficult. Let's hence issue a manual sync here, so that we at least can
         * guarantee the file systems that are about to become unreachable are in a good state before
         * entering this state. See sync_departing_file_systems() above for why we don't just call the
         * global sync() here unconditionally: only fall back to it if the smarter, targeted sync couldn't
         * be performed (e.g. libmount is unavailable, or /proc/self/mountinfo couldn't be parsed). */
        if (!FLAGS_SET(flags, SWITCH_ROOT_DONT_SYNC)) {
                r = sync_departing_file_systems(new_root);
                if (r < 0) {
                        log_debug_errno(r, "Failed to selectively synchronize departing file systems, falling back to global sync(): %m");
                        sync();
                }
        }

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

                if (FLAGS_SET(flags, SWITCH_ROOT_RECURSIVE_RUN) && transfer->skip_recursive_run)
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

                if (FLAGS_SET(flags, SWITCH_ROOT_RECURSIVE_RUN)) {
                        /* On recursive runs, first create a bind mount with MOVE_MOUNT_BENEATH, and then MS_MOVE
                         * the original mount point to the new root. This ensures that the mount point in the final
                         * destination is the original mount, but also ensures that the mount is available in the old
                         * root during the switch root. The latter is true because when we MS_MOVE, the bind mount is revelead. */
                        _cleanup_close_ int mnt_fd = -EBADF, target_fd = -EBADF;

                        target_fd = open(transfer->path, O_PATH|O_NOFOLLOW|O_CLOEXEC);
                        if (target_fd < 0)
                                return log_error_errno(errno, "Failed to open '%s': %m", transfer->path);

                        mnt_fd = open_tree(-EBADF, transfer->path, OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC);
                        if (mnt_fd < 0)
                                return log_error_errno(errno, "Failed to open_tree '%s': %m", transfer->path);

                        r = RET_NERRNO(mount_setattr(mnt_fd, "", AT_EMPTY_PATH,
                                                     &(struct mount_attr) { .propagation = 0 },
                                                     MOUNT_ATTR_SIZE_VER0));
                        if (r < 0)
                                return log_error_errno(r, "Failed to set mount attrs: %m");

                        r = RET_NERRNO(move_mount(mnt_fd, "",
                                                  target_fd, "",
                                                  MOVE_MOUNT_BENEATH|MOVE_MOUNT_F_EMPTY_PATH|MOVE_MOUNT_T_EMPTY_PATH));
                        if (r == -EINVAL)
                                log_warning_errno(r, "Failed to move bind mount beneath '%s', ignoring: %m", transfer->path);
                        else if (r < 0)
                                return log_debug_errno(r, "Failed to move bind mount beneath '%s': %m", transfer->path);

                        r = mount_nofollow_verbose(LOG_ERR, transfer->path, chased, NULL, MS_MOVE, NULL);
                        if (r < 0)
                                return r;
                } else {
                        r = mount_nofollow_verbose(LOG_ERR, transfer->path, chased, NULL, transfer->mount_flags, NULL);
                        if (r < 0)
                                return r;
                }

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

                /* Now empty the old root superblock */
                if (istmp > 0) {
                        struct stat rb;

                        if (fstat(old_root_fd, &rb) < 0)
                                return log_error_errno(errno, "Failed to stat old root directory: %m");

                        /* Note: the below won't operate on non-memory file systems (i.e. only on tmpfs, ramfs), and
                         * it will stop at mount boundaries */
                        (void) rm_rf_children(TAKE_FD(old_root_fd), 0, &rb); /* takes possession of the dir fd, even on failure */
                }
        } else
                /* NB: we don't bother with emptying the old root superblock here, under the assumption the
                 * pivot_root() + umount() sufficiently detached from the superblock to the point we don't
                 * need to empty it anymore */
                log_debug("Pivoting root worked.");

        return 0;
}
