/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "dissect-image.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "fs-util.h"
#include "fstab-util.h"
#include "glyph-util.h"
#include "hashmap.h"
#include "libmount-util.h"
#include "log.h"
#include "missing_syscall.h"
#include "mkdir-label.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "os-util.h"
#include "path-util.h"
#include "pidref.h"
#include "process-util.h"
#include "set.h"
#include "sort-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

int umount_recursive_full(const char *prefix, int flags, char **keep) {
        _cleanup_fclose_ FILE *f = NULL;
        int n = 0, r;

        /* Try to umount everything recursively below a directory. Also, take care of stacked mounts, and
         * keep unmounting them until they are gone. */

        f = fopen("/proc/self/mountinfo", "re"); /* Pin the file, in case we unmount /proc/ as part of the logic here */
        if (!f)
                return log_debug_errno(errno, "Failed to open %s: %m", "/proc/self/mountinfo");

        for (;;) {
                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                bool again = false;

                r = libmount_parse_mountinfo(f, &table, &iter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

                for (;;) {
                        bool shall_keep = false;
                        struct libmnt_fs *fs;
                        const char *path;

                        r = mnt_table_next_fs(table, iter, &fs);
                        if (r == 1)
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                        path = mnt_fs_get_target(fs);
                        if (!path)
                                continue;

                        if (prefix && !path_startswith(path, prefix)) {
                                // FIXME: This is extremely noisy, we're probably doing something very wrong
                                // to trigger this so often, needs more investigation.
                                // log_trace("Not unmounting %s, outside of prefix: %s", path, prefix);
                                continue;
                        }

                        STRV_FOREACH(k, keep)
                                /* Match against anything in the path to the dirs to keep, or below the dirs to keep */
                                if (path_startswith(path, *k) || path_startswith(*k, path)) {
                                        shall_keep = true;
                                        break;
                                }
                        if (shall_keep) {
                                log_debug("Not unmounting %s, referenced by keep list.", path);
                                continue;
                        }

                        if (umount2(path, flags | UMOUNT_NOFOLLOW) < 0) {
                                log_debug_errno(errno, "Failed to umount %s, ignoring: %m", path);
                                continue;
                        }

                        log_trace("Successfully unmounted %s", path);

                        again = true;
                        n++;

                        break;
                }

                if (!again)
                        break;

                rewind(f);
        }

        return n;
}

#define MS_CONVERTIBLE_FLAGS (MS_RDONLY|MS_NOSUID|MS_NODEV|MS_NOEXEC|MS_NOSYMFOLLOW)

static uint64_t ms_flags_to_mount_attr(unsigned long a) {
        uint64_t f = 0;

        if (FLAGS_SET(a, MS_RDONLY))
                f |= MOUNT_ATTR_RDONLY;

        if (FLAGS_SET(a, MS_NOSUID))
                f |= MOUNT_ATTR_NOSUID;

        if (FLAGS_SET(a, MS_NODEV))
                f |= MOUNT_ATTR_NODEV;

        if (FLAGS_SET(a, MS_NOEXEC))
                f |= MOUNT_ATTR_NOEXEC;

        if (FLAGS_SET(a, MS_NOSYMFOLLOW))
                f |= MOUNT_ATTR_NOSYMFOLLOW;

        return f;
}

static bool skip_mount_set_attr = false;

/* Use this function only if you do not have direct access to /proc/self/mountinfo but the caller can open it
 * for you. This is the case when /proc is masked or not mounted. Otherwise, use bind_remount_recursive. */
int bind_remount_recursive_with_mountinfo(
                const char *prefix,
                unsigned long new_flags,
                unsigned long flags_mask,
                char **deny_list,
                FILE *proc_self_mountinfo) {

        _cleanup_fclose_ FILE *proc_self_mountinfo_opened = NULL;
        _cleanup_set_free_ Set *done = NULL;
        unsigned n_tries = 0;
        int r;

        assert(prefix);

        if ((flags_mask & ~MS_CONVERTIBLE_FLAGS) == 0 && strv_isempty(deny_list) && !skip_mount_set_attr) {
                /* Let's take a shortcut for all the flags we know how to convert into mount_setattr() flags */

                if (mount_setattr(AT_FDCWD, prefix, AT_SYMLINK_NOFOLLOW|AT_RECURSIVE,
                                  &(struct mount_attr) {
                                          .attr_set = ms_flags_to_mount_attr(new_flags & flags_mask),
                                          .attr_clr = ms_flags_to_mount_attr(~new_flags & flags_mask),
                                  }, MOUNT_ATTR_SIZE_VER0) < 0) {

                        log_debug_errno(errno, "mount_setattr() failed, falling back to classic remounting: %m");

                        /* We fall through to classic behaviour if not supported (i.e. kernel < 5.12). We
                         * also do this for all other kinds of errors since they are so many different, and
                         * mount_setattr() has no graceful mode where it continues despite seeing errors one
                         * some mounts, but we want that. Moreover mount_setattr() only works on the mount
                         * point inode itself, not a non-mount point inode, and we want to support arbitrary
                         * prefixes here. */

                        if (ERRNO_IS_NOT_SUPPORTED(errno)) /* if not supported, then don't bother at all anymore */
                                skip_mount_set_attr = true;
                } else
                        return 0; /* Nice, this worked! */
        }

        if (!proc_self_mountinfo) {
                r = fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo_opened);
                if (r < 0)
                        return r;

                proc_self_mountinfo = proc_self_mountinfo_opened;
        }

        /* Recursively remount a directory (and all its submounts) with desired flags (MS_READONLY,
         * MS_NOSUID, MS_NOEXEC). If the directory is already mounted, we reuse the mount and simply mark it
         * MS_BIND|MS_RDONLY (or remove the MS_RDONLY for read-write operation), ditto for other flags. If it
         * isn't we first make it one. Afterwards we apply (or remove) the flags to all submounts we can
         * access, too. When mounts are stacked on the same mount point we only care for each individual
         * "top-level" mount on each point, as we cannot influence/access the underlying mounts anyway. We do
         * not have any effect on future submounts that might get propagated, they might be writable
         * etc. This includes future submounts that have been triggered via autofs. Also note that we can't
         * operate atomically here. Mounts established while we process the tree might or might not get
         * noticed and thus might or might not be covered.
         *
         * If the "deny_list" parameter is specified it may contain a list of subtrees to exclude from the
         * remount operation. Note that we'll ignore the deny list for the top-level path. */

        for (;;) {
                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                _cleanup_hashmap_free_ Hashmap *todo = NULL;
                bool top_autofs = false;

                if (n_tries++ >= 32) /* Let's not retry this loop forever */
                        return -EBUSY;

                rewind(proc_self_mountinfo);

                r = libmount_parse_mountinfo(proc_self_mountinfo, &table, &iter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

                for (;;) {
                        _cleanup_free_ char *d = NULL;
                        const char *path, *type, *opts;
                        unsigned long flags = 0;
                        struct libmnt_fs *fs;

                        r = mnt_table_next_fs(table, iter, &fs);
                        if (r == 1) /* EOF */
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                        path = mnt_fs_get_target(fs);
                        if (!path)
                                continue;

                        if (!path_startswith(path, prefix))
                                continue;

                        type = mnt_fs_get_fstype(fs);
                        if (!type)
                                continue;

                        /* Let's ignore autofs mounts. If they aren't triggered yet, we want to avoid
                         * triggering them, as we don't make any guarantees for future submounts anyway. If
                         * they are already triggered, then we will find another entry for this. */
                        if (streq(type, "autofs")) {
                                top_autofs = top_autofs || path_equal(path, prefix);
                                continue;
                        }

                        if (set_contains(done, path))
                                continue;

                        /* Ignore this mount if it is deny-listed, but only if it isn't the top-level mount
                         * we shall operate on. */
                        if (!path_equal(path, prefix)) {
                                bool deny_listed = false;

                                STRV_FOREACH(i, deny_list) {
                                        if (path_equal(*i, prefix))
                                                continue;

                                        if (!path_startswith(*i, prefix))
                                                continue;

                                        if (path_startswith(path, *i)) {
                                                deny_listed = true;
                                                log_trace("Not remounting %s deny-listed by %s, called for %s", path, *i, prefix);
                                                break;
                                        }
                                }

                                if (deny_listed)
                                        continue;
                        }

                        opts = mnt_fs_get_vfs_options(fs);
                        if (opts) {
                                r = mnt_optstr_get_flags(opts, &flags, mnt_get_builtin_optmap(MNT_LINUX_MAP));
                                if (r < 0)
                                        log_debug_errno(r, "Could not get flags for '%s', ignoring: %m", path);
                        }

                        d = strdup(path);
                        if (!d)
                                return -ENOMEM;

                        r = hashmap_ensure_put(&todo, &path_hash_ops_free, d, ULONG_TO_PTR(flags));
                        if (r == -EEXIST)
                                /* If the same path was recorded, but with different mount flags, update it:
                                 * it means a mount point is overmounted, and libmount returns the "bottom" (or
                                 * older one) first, but we want to reapply the flags from the "top" (or newer
                                 * one). See: https://github.com/systemd/systemd/issues/20032
                                 * Note that this shouldn't really fail, as we were just told that the key
                                 * exists, and it's an update so we want 'd' to be freed immediately. */
                                r = hashmap_update(todo, d, ULONG_TO_PTR(flags));
                        if (r < 0)
                                return r;
                        if (r > 0)
                                TAKE_PTR(d);
                }

                /* Check if the top-level directory was among what we have seen so far. For that check both
                 * 'done' and 'todo'. Also check 'top_autofs' because if the top-level dir is an autofs we'll
                 * not include it in either set but will set this bool. */
                if (!set_contains(done, prefix) &&
                    !(top_autofs || hashmap_contains(todo, prefix))) {

                        /* The prefix directory itself is not yet a mount, make it one. */
                        r = mount_nofollow(prefix, prefix, NULL, MS_BIND|MS_REC, NULL);
                        if (r < 0)
                                return r;

                        /* Immediately rescan, so that we pick up the new mount's flags */
                        continue;
                }

                /* If we have no submounts to process anymore, we are done */
                if (hashmap_isempty(todo))
                        return 0;

                for (;;) {
                        unsigned long flags;
                        char *x = NULL;

                        /* Take the first mount from our list of mounts to still process */
                        flags = PTR_TO_ULONG(hashmap_steal_first_key_and_value(todo, (void**) &x));
                        if (!x)
                                break;

                        r = set_ensure_consume(&done, &path_hash_ops_free, x);
                        if (IN_SET(r, 0, -EEXIST))
                                continue; /* Already done */
                        if (r < 0)
                                return r;

                        /* Now, remount this with the new flags set, but exclude MS_RELATIME from it. (It's
                         * the default anyway, thus redundant, and in userns we'll get an error if we try to
                         * explicitly enable it) */
                        r = mount_nofollow(NULL, x, NULL, ((flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags) & ~MS_RELATIME, NULL);
                        if (r < 0) {
                                int q;

                                /* OK, so the remount of this entry failed. We'll ultimately ignore this in
                                 * almost all cases (there are simply so many reasons why this can fail,
                                 * think autofs, NFS, FUSE, …), but let's generate useful debug messages at
                                 * the very least. */

                                q = path_is_mount_point(x);
                                if (IN_SET(q, 0, -ENOENT)) {
                                        /* Hmm, whaaaa? The mount point is not actually a mount point? Then
                                         * it is either obstructed by a later mount or somebody has been
                                         * racing against us and removed it. Either way the mount point
                                         * doesn't matter to us, let's ignore it hence. */
                                        log_debug_errno(r, "Mount point '%s' to remount is not a mount point anymore, ignoring remount failure: %m", x);
                                        continue;
                                }
                                if (q < 0) /* Any other error on this? Just log and continue */
                                        log_debug_errno(q, "Failed to determine whether '%s' is a mount point or not, ignoring: %m", x);

                                if (((flags ^ new_flags) & flags_mask & ~MS_RELATIME) == 0) { /* ignore MS_RELATIME while comparing */
                                        log_debug_errno(r, "Couldn't remount '%s', but the flags already match what we want, hence ignoring: %m", x);
                                        continue;
                                }

                                /* Make this fatal if this is the top-level mount */
                                if (path_equal(x, prefix))
                                        return r;

                                /* If this is not the top-level mount, then handle this gracefully: log but
                                 * otherwise ignore. With NFS, FUSE, autofs there are just too many reasons
                                 * this might fail without a chance for us to do anything about it, let's
                                 * hence be strict on the top-level mount and lenient on the inner ones. */
                                log_debug_errno(r, "Couldn't remount submount '%s' for unexpected reason, ignoring: %m", x);
                                continue;
                        }

                        log_trace("Remounted %s.", x);
                }
        }
}

int bind_remount_one_with_mountinfo(
                const char *path,
                unsigned long new_flags,
                unsigned long flags_mask,
                FILE *proc_self_mountinfo) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        unsigned long flags = 0;
        struct libmnt_fs *fs;
        const char *opts;
        int r;

        assert(path);
        assert(proc_self_mountinfo);

        if ((flags_mask & ~MS_CONVERTIBLE_FLAGS) == 0 && !skip_mount_set_attr) {
                /* Let's take a shortcut for all the flags we know how to convert into mount_setattr() flags */

                if (mount_setattr(AT_FDCWD, path, AT_SYMLINK_NOFOLLOW,
                                  &(struct mount_attr) {
                                          .attr_set = ms_flags_to_mount_attr(new_flags & flags_mask),
                                          .attr_clr = ms_flags_to_mount_attr(~new_flags & flags_mask),
                                  }, MOUNT_ATTR_SIZE_VER0) < 0) {

                        log_debug_errno(errno, "mount_setattr() didn't work, falling back to classic remounting: %m");

                        if (ERRNO_IS_NOT_SUPPORTED(errno)) /* if not supported, then don't bother at all anymore */
                                skip_mount_set_attr = true;
                } else
                        return 0; /* Nice, this worked! */
        }

        rewind(proc_self_mountinfo);

        table = mnt_new_table();
        if (!table)
                return -ENOMEM;

        r = mnt_table_parse_stream(table, proc_self_mountinfo, "/proc/self/mountinfo");
        if (r < 0)
                return r;

        fs = mnt_table_find_target(table, path, MNT_ITER_FORWARD);
        if (!fs) {
                r = access_nofollow(path, F_OK); /* Hmm, it's not in the mount table, but does it exist at all? */
                if (r < 0)
                        return r;

                return -EINVAL; /* Not a mount point we recognize */
        }

        opts = mnt_fs_get_vfs_options(fs);
        if (opts) {
                r = mnt_optstr_get_flags(opts, &flags, mnt_get_builtin_optmap(MNT_LINUX_MAP));
                if (r < 0)
                        log_debug_errno(r, "Could not get flags for '%s', ignoring: %m", path);
        }

        r = mount_nofollow(NULL, path, NULL, ((flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags) & ~MS_RELATIME, NULL);
        if (r < 0) {
                if (((flags ^ new_flags) & flags_mask & ~MS_RELATIME) != 0) /* Ignore MS_RELATIME again,
                                                                             * since kernel adds it in
                                                                             * everywhere, because it's the
                                                                             * default. */
                        return r;

                /* Let's handle redundant remounts gracefully */
                log_debug_errno(r, "Failed to remount '%s' but flags already match what we want, ignoring: %m", path);
        }

        return 0;
}

int bind_remount_one(const char *path, unsigned long new_flags, unsigned long flags_mask) {
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo)
                return log_debug_errno(errno, "Failed to open %s: %m", "/proc/self/mountinfo");

        return bind_remount_one_with_mountinfo(path, new_flags, flags_mask, proc_self_mountinfo);
}

static int mount_switch_root_pivot(int fd_newroot, const char *path) {
        assert(fd_newroot >= 0);
        assert(path);

        /* Let the kernel tuck the new root under the old one. */
        if (pivot_root(".", ".") < 0)
                return log_debug_errno(errno, "Failed to pivot root to new rootfs '%s': %m", path);

        /* Get rid of the old root and reveal our brand new root. (This will always operate on the top-most
         * mount on our cwd, regardless what our current directory actually points to.) */
        if (umount2(".", MNT_DETACH) < 0)
                return log_debug_errno(errno, "Failed to unmount old rootfs: %m");

        return 0;
}

static int mount_switch_root_move(int fd_newroot, const char *path) {
        assert(fd_newroot >= 0);
        assert(path);

        /* Move the new root fs */
        if (mount(".", "/", NULL, MS_MOVE, NULL) < 0)
                return log_debug_errno(errno, "Failed to move new rootfs '%s': %m", path);

        /* Also change root dir */
        if (chroot(".") < 0)
                return log_debug_errno(errno, "Failed to chroot to new rootfs '%s': %m", path);

        return 0;
}

int mount_switch_root_full(const char *path, unsigned long mount_propagation_flag, bool force_ms_move) {
        _cleanup_close_ int fd_newroot = -EBADF;
        int r, is_current_root;

        assert(path);
        assert(mount_propagation_flag_is_valid(mount_propagation_flag));

        fd_newroot = open(path, O_PATH|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW);
        if (fd_newroot < 0)
                return log_debug_errno(errno, "Failed to open new rootfs '%s': %m", path);

        is_current_root = path_is_root_at(fd_newroot, NULL);
        if (is_current_root < 0)
                return log_debug_errno(is_current_root, "Failed to determine if target dir is our root already: %m");

        /* Change into the new rootfs. */
        if (fchdir(fd_newroot) < 0)
                return log_debug_errno(errno, "Failed to chdir into new rootfs '%s': %m", path);

        /* Make this a NOP if we are supposed to switch to our current root fs. After all, both pivot_root()
         * and MS_MOVE don't like that. */
        if (!is_current_root) {
                if (!force_ms_move) {
                        r = mount_switch_root_pivot(fd_newroot, path);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to pivot into new rootfs '%s', will try to use MS_MOVE instead: %m", path);
                                force_ms_move = true;
                        }
                }
                if (force_ms_move) {
                        /* Failed to pivot_root() fallback to MS_MOVE. For example, this may happen if the rootfs is
                         * an initramfs in which case pivot_root() isn't supported. */
                        r = mount_switch_root_move(fd_newroot, path);
                        if (r < 0)
                                return log_debug_errno(r, "Failed to switch to new rootfs '%s' with MS_MOVE: %m", path);
                }
        }

        log_debug("Successfully switched root to '%s'.", path);

        /* Finally, let's establish the requested propagation flags. */
        if (mount_propagation_flag == 0)
                return 0;

        if (mount(NULL, ".", NULL, mount_propagation_flag | MS_REC, NULL) < 0)
                return log_debug_errno(errno, "Failed to turn new rootfs '%s' into %s mount: %m",
                                       mount_propagation_flag_to_string(mount_propagation_flag), path);

        return 0;
}

int repeat_unmount(const char *path, int flags) {
        bool done = false;

        assert(path);

        /* If there are multiple mounts on a mount point, this
         * removes them all */

        for (;;) {
                if (umount2(path, flags) < 0) {

                        if (errno == EINVAL)
                                return done;

                        return -errno;
                }

                done = true;
        }
}

int mode_to_inaccessible_node(
                const char *runtime_dir,
                mode_t mode,
                char **ret) {

        /* This function maps a node type to a corresponding inaccessible file node. These nodes are created
         * during early boot by PID 1. In some cases we lacked the privs to create the character and block
         * devices (maybe because we run in an userns environment, or miss CAP_SYS_MKNOD, or run with a
         * devices policy that excludes device nodes with major and minor of 0), but that's fine, in that
         * case we use an AF_UNIX file node instead, which is not the same, but close enough for most
         * uses. And most importantly, the kernel allows bind mounts from socket nodes to any non-directory
         * file nodes, and that's the most important thing that matters.
         *
         * Note that the runtime directory argument shall be the top-level runtime directory, i.e. /run/ if
         * we operate in system context and $XDG_RUNTIME_DIR if we operate in user context. */

        _cleanup_free_ char *d = NULL;
        const char *node;

        assert(ret);

        if (!runtime_dir)
                runtime_dir = "/run";

        if (S_ISLNK(mode))
                return -EINVAL;

        node = inode_type_to_string(mode);
        if (!node)
                return -EINVAL;

        d = path_join(runtime_dir, "systemd/inaccessible", node);
        if (!d)
                return -ENOMEM;

        /* On new kernels unprivileged users are permitted to create 0:0 char device nodes (because they also
         * act as whiteout inode for overlayfs), but no other char or block device nodes. On old kernels no
         * device node whatsoever may be created by unprivileged processes. Hence, if the caller asks for the
         * inaccessible block device node let's see if the block device node actually exists, and if not,
         * fall back to the character device node. From there fall back to the socket device node. This means
         * in the best case we'll get the right device node type — but if not we'll hopefully at least get a
         * device node at all. */

        if (S_ISBLK(mode) &&
            access(d, F_OK) < 0 && errno == ENOENT) {
                free(d);
                d = path_join(runtime_dir, "/systemd/inaccessible/chr");
                if (!d)
                        return -ENOMEM;
        }

        if (IN_SET(mode & S_IFMT, S_IFBLK, S_IFCHR) &&
            access(d, F_OK) < 0 && errno == ENOENT) {
                free(d);
                d = path_join(runtime_dir, "/systemd/inaccessible/sock");
                if (!d)
                        return -ENOMEM;
        }

        *ret = TAKE_PTR(d);
        return 0;
}

int mount_flags_to_string(unsigned long flags, char **ret) {
        static const struct {
                unsigned long flag;
                const char *name;
        } map[] = {
                { .flag = MS_RDONLY,      .name = "MS_RDONLY",      },
                { .flag = MS_NOSUID,      .name = "MS_NOSUID",      },
                { .flag = MS_NODEV,       .name = "MS_NODEV",       },
                { .flag = MS_NOEXEC,      .name = "MS_NOEXEC",      },
                { .flag = MS_SYNCHRONOUS, .name = "MS_SYNCHRONOUS", },
                { .flag = MS_REMOUNT,     .name = "MS_REMOUNT",     },
                { .flag = MS_MANDLOCK,    .name = "MS_MANDLOCK",    },
                { .flag = MS_DIRSYNC,     .name = "MS_DIRSYNC",     },
                { .flag = MS_NOSYMFOLLOW, .name = "MS_NOSYMFOLLOW", },
                { .flag = MS_NOATIME,     .name = "MS_NOATIME",     },
                { .flag = MS_NODIRATIME,  .name = "MS_NODIRATIME",  },
                { .flag = MS_BIND,        .name = "MS_BIND",        },
                { .flag = MS_MOVE,        .name = "MS_MOVE",        },
                { .flag = MS_REC,         .name = "MS_REC",         },
                { .flag = MS_SILENT,      .name = "MS_SILENT",      },
                { .flag = MS_POSIXACL,    .name = "MS_POSIXACL",    },
                { .flag = MS_UNBINDABLE,  .name = "MS_UNBINDABLE",  },
                { .flag = MS_PRIVATE,     .name = "MS_PRIVATE",     },
                { .flag = MS_SLAVE,       .name = "MS_SLAVE",       },
                { .flag = MS_SHARED,      .name = "MS_SHARED",      },
                { .flag = MS_RELATIME,    .name = "MS_RELATIME",    },
                { .flag = MS_KERNMOUNT,   .name = "MS_KERNMOUNT",   },
                { .flag = MS_I_VERSION,   .name = "MS_I_VERSION",   },
                { .flag = MS_STRICTATIME, .name = "MS_STRICTATIME", },
                { .flag = MS_LAZYTIME,    .name = "MS_LAZYTIME",    },
        };
        _cleanup_free_ char *str = NULL;

        assert(ret);

        FOREACH_ELEMENT(entry, map)
                if (flags & entry->flag) {
                        if (!strextend_with_separator(&str, "|", entry->name))
                                return -ENOMEM;
                        flags &= ~entry->flag;
                }

        if (!str || flags != 0)
                if (strextendf_with_separator(&str, "|", "%lx", flags) < 0)
                        return -ENOMEM;

        *ret = TAKE_PTR(str);
        return 0;
}

int mount_verbose_full(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options,
                bool follow_symlink) {

        _cleanup_free_ char *fl = NULL, *o = NULL;
        unsigned long f;
        int r;

        r = mount_option_mangle(options, flags, &f, &o);
        if (r < 0)
                return log_full_errno(error_log_level, r,
                                      "Failed to mangle mount options %s: %m",
                                      strempty(options));

        (void) mount_flags_to_string(f, &fl);

        if (FLAGS_SET(f, MS_REMOUNT|MS_BIND))
                log_debug("Changing mount flags %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if (f & MS_REMOUNT)
                log_debug("Remounting superblock %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if (f & (MS_SHARED|MS_PRIVATE|MS_SLAVE|MS_UNBINDABLE))
                log_debug("Changing mount propagation %s (%s \"%s\")",
                          where, strnull(fl), strempty(o));
        else if (f & MS_BIND)
                log_debug("Bind-mounting %s on %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
        else if (f & MS_MOVE)
                log_debug("Moving mount %s %s %s (%s \"%s\")...",
                          what, glyph(GLYPH_ARROW_RIGHT), where, strnull(fl), strempty(o));
        else
                log_debug("Mounting %s (%s) on %s (%s \"%s\")...",
                          strna(what), strna(type), where, strnull(fl), strempty(o));

        if (follow_symlink)
                r = RET_NERRNO(mount(what, where, type, f, o));
        else
                r = mount_nofollow(what, where, type, f, o);
        if (r < 0)
                return log_full_errno(error_log_level, r,
                                      "Failed to mount %s (type %s) on %s (%s \"%s\"): %m",
                                      strna(what), strna(type), where, strnull(fl), strempty(o));
        return 0;
}

int umount_verbose(
                int error_log_level,
                const char *where,
                int flags) {

        assert(where);

        log_debug("Unmounting '%s'...", where);

        if (umount2(where, flags) < 0)
                return log_full_errno(error_log_level, errno, "Failed to unmount '%s': %m", where);

        return 0;
}

int umountat_detach_verbose(
                int error_log_level,
                int fd,
                const char *where) {

        /* Similar to umountat_verbose(), but goes by fd + path. This implies MNT_DETACH, since to do this we
         * must pin the inode in question via an fd. */

        assert(fd >= 0 || fd == AT_FDCWD);

        /* If neither fd nor path are specified take this as reference to the cwd */
        if (fd == AT_FDCWD && isempty(where))
                return umount_verbose(error_log_level, ".", MNT_DETACH|UMOUNT_NOFOLLOW);

        /* If we don't actually take the fd into consideration for this operation shortcut things, so that we
         * don't have to open the inode */
        if (fd == AT_FDCWD || path_is_absolute(where))
                return umount_verbose(error_log_level, where, MNT_DETACH|UMOUNT_NOFOLLOW);

        _cleanup_free_ char *prefix = NULL;
        const char *p;
        if (fd_get_path(fd, &prefix) < 0)
                p = "<fd>"; /* if we can't get the path, return something vaguely useful */
        else
                p = prefix;
        _cleanup_free_ char *joined = isempty(where) ? strdup(p) : path_join(p, where);

        log_debug("Unmounting '%s'...", strna(joined));

        _cleanup_close_ int inode_fd = -EBADF;
        int mnt_fd;
        if (isempty(where))
                mnt_fd = fd;
        else {
                inode_fd = openat(fd, where, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (inode_fd < 0)
                        return log_full_errno(error_log_level, errno, "Failed to pin '%s': %m", strna(joined));

                mnt_fd = inode_fd;
        }

        if (umount2(FORMAT_PROC_FD_PATH(mnt_fd), MNT_DETACH) < 0)
                return log_full_errno(error_log_level, errno, "Failed to unmount '%s': %m", strna(joined));

        return 0;
}

int mount_exchange_graceful(int fsmount_fd, const char *dest, bool mount_beneath) {
        int r;

        assert(fsmount_fd >= 0);
        assert(dest);

        /* First, try to mount beneath an existing mount point, and if that works, umount the old mount,
         * which is now at the top. This will ensure we can atomically replace a mount. Note that this works
         * also in the case where there are submounts down the tree. Mount propagation is allowed but
         * restricted to layouts that don't end up propagation the new mount on top of the mount stack.  If
         * this is not supported (minimum kernel v6.5), or if there is no mount on the mountpoint, we get
         * -EINVAL and then we fallback to normal mounting. */

        r = RET_NERRNO(move_mount(fsmount_fd, /* from_path = */ "",
                                  /* to_fd = */ -EBADF, dest,
                                  MOVE_MOUNT_F_EMPTY_PATH | (mount_beneath ? MOVE_MOUNT_BENEATH : 0)));
        if (mount_beneath) {
                if (r >= 0) /* Mounting beneath worked! Now unmount the upper mount. */
                        return umount_verbose(LOG_DEBUG, dest, UMOUNT_NOFOLLOW|MNT_DETACH);

                if (r == -EINVAL) { /* Fallback if mount_beneath is not supported */
                        log_debug_errno(r,
                                        "Cannot mount beneath '%s', falling back to overmount: %m",
                                        dest);
                        return mount_exchange_graceful(fsmount_fd, dest, /* mount_beneath = */ false);
                }
        }

        return r;
}

int mount_option_mangle(
                const char *options,
                unsigned long mount_flags,
                unsigned long *ret_mount_flags,
                char **ret_remaining_options) {

        const struct libmnt_optmap *map;
        _cleanup_free_ char *ret = NULL;
        int r;

        /* This extracts mount flags from the mount options, and stores
         * non-mount-flag options to '*ret_remaining_options'.
         * E.g.,
         * "rw,nosuid,nodev,relatime,size=1630748k,mode=0700,uid=1000,gid=1000"
         * is split to MS_NOSUID|MS_NODEV|MS_RELATIME and
         * "size=1630748k,mode=0700,uid=1000,gid=1000".
         * See more examples in test-mount-util.c.
         *
         * If 'options' does not contain any non-mount-flag options,
         * then '*ret_remaining_options' is set to NULL instead of empty string.
         * The validity of options stored in '*ret_remaining_options' is not checked.
         * If 'options' is NULL, this just copies 'mount_flags' to *ret_mount_flags. */

        assert(ret_mount_flags);
        assert(ret_remaining_options);

        map = mnt_get_builtin_optmap(MNT_LINUX_MAP);
        if (!map)
                return -EINVAL;

        for (const char *p = options;;) {
                _cleanup_free_ char *word = NULL;
                const struct libmnt_optmap *ent;

                r = extract_first_word(&p, &word, ",", EXTRACT_KEEP_QUOTE);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                for (ent = map; ent->name; ent++) {
                        /* All entries in MNT_LINUX_MAP do not take any argument.
                         * Thus, ent->name does not contain "=" or "[=]". */
                        if (!streq(word, ent->name))
                                continue;

                        if (!(ent->mask & MNT_INVERT))
                                mount_flags |= ent->id;
                        else
                                mount_flags &= ~ent->id;

                        break;
                }

                /* If 'word' is not a mount flag, then store it in '*ret_remaining_options'. */
                if (!ent->name &&
                    !startswith_no_case(word, "x-") &&
                    !strextend_with_separator(&ret, ",", word))
                        return -ENOMEM;
        }

        *ret_mount_flags = mount_flags;
        *ret_remaining_options = TAKE_PTR(ret);

        return 0;
}

static int mount_in_namespace_legacy(
                const char *chased_src_path,
                int chased_src_fd,
                struct stat *chased_src_st,
                const char *propagate_path,
                const char *incoming_path,
                const char *dest,
                int pidns_fd,
                int mntns_fd,
                int root_fd,
                MountInNamespaceFlags flags,
                const MountOptions *options,
                const ImagePolicy *image_policy) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        pid_t child;
        int r;

        assert(chased_src_path);
        assert(chased_src_fd >= 0);
        assert(chased_src_st);
        assert(propagate_path);
        assert(incoming_path);
        assert(dest);
        assert(pidns_fd >= 0);
        assert(mntns_fd >= 0);
        assert(root_fd >= 0);
        assert(!options || (flags & MOUNT_IN_NAMESPACE_IS_IMAGE));

        p = strjoina(propagate_path, "/");
        r = access_nofollow(p, F_OK);
        if (r < 0)
                return log_debug_errno(r == -ENOENT ? SYNTHETIC_ERRNO(EOPNOTSUPP) : r, "Target does not allow propagation of mount points");

        /* Our goal is to install a new bind mount into the container,
           possibly read-only. This is irritatingly complex
           unfortunately, currently.

           First, we start by creating a private playground in /tmp,
           that we can mount MS_SLAVE. (Which is necessary, since
           MS_MOVE cannot be applied to mounts with MS_SHARED parent
           mounts.) */

        if (!mkdtemp(mount_slave))
                return log_debug_errno(errno, "Failed to create playground %s: %m", mount_slave);

        mount_slave_created = true;

        r = mount_nofollow_verbose(LOG_DEBUG, mount_slave, mount_slave, NULL, MS_BIND, NULL);
        if (r < 0)
                goto finish;

        mount_slave_mounted = true;

        r = mount_nofollow_verbose(LOG_DEBUG, NULL, mount_slave, NULL, MS_SLAVE, NULL);
        if (r < 0)
                goto finish;

        /* Second, we mount the source file or directory to a directory inside of our MS_SLAVE playground. */
        mount_tmp = strjoina(mount_slave, "/mount");
        r = make_mount_point_inode_from_mode(AT_FDCWD, mount_tmp, (flags & MOUNT_IN_NAMESPACE_IS_IMAGE) ? S_IFDIR : chased_src_st->st_mode, 0700);
        if (r < 0) {
                log_debug_errno(r, "Failed to create temporary mount point %s: %m", mount_tmp);
                goto finish;
        }

        mount_tmp_created = true;

        if (flags & MOUNT_IN_NAMESPACE_IS_IMAGE)
                r = verity_dissect_and_mount(
                                chased_src_fd,
                                chased_src_path,
                                mount_tmp,
                                options,
                                image_policy,
                                /* image_filter= */ NULL,
                                /* extension_release_data= */ NULL,
                                /* required_class= */ _IMAGE_CLASS_INVALID,
                                /* verity= */ NULL,
                                /* ret_image= */ NULL);
        else
                r = mount_follow_verbose(LOG_DEBUG, FORMAT_PROC_FD_PATH(chased_src_fd), mount_tmp, NULL, MS_BIND, NULL);
        if (r < 0)
                goto finish;

        mount_tmp_mounted = true;

        /* Third, we remount the new bind mount read-only if requested. */
        if (flags & MOUNT_IN_NAMESPACE_READ_ONLY) {
                r = mount_nofollow_verbose(LOG_DEBUG, NULL, mount_tmp, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
                if (r < 0)
                        goto finish;
        }

        /* Fourth, we move the new bind mount into the propagation directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strjoina(propagate_path, "/XXXXXX");
        if ((flags & MOUNT_IN_NAMESPACE_IS_IMAGE) || S_ISDIR(chased_src_st->st_mode))
                r = mkdtemp(mount_outside) ? 0 : -errno;
        else {
                r = mkostemp_safe(mount_outside);
                safe_close(r);
        }
        if (r < 0) {
                log_debug_errno(r, "Cannot create propagation file or directory %s: %m", mount_outside);
                goto finish;
        }

        mount_outside_created = true;

        r = mount_nofollow_verbose(LOG_DEBUG, mount_tmp, mount_outside, NULL, MS_MOVE, NULL);
        if (r < 0)
                goto finish;

        mount_outside_mounted = true;
        mount_tmp_mounted = false;

        if ((flags & MOUNT_IN_NAMESPACE_IS_IMAGE) || S_ISDIR(chased_src_st->st_mode))
                (void) rmdir(mount_tmp);
        else
                (void) unlink(mount_tmp);
        mount_tmp_created = false;

        (void) umount_verbose(LOG_DEBUG, mount_slave, UMOUNT_NOFOLLOW);
        mount_slave_mounted = false;

        (void) rmdir(mount_slave);
        mount_slave_created = false;

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0) {
                log_debug_errno(errno, "Failed to create pipe: %m");
                goto finish;
        }

        r = namespace_fork(
                        "(sd-bindmnt)",
                        "(sd-bindmnt-inner)",
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM,
                        pidns_fd,
                        mntns_fd,
                        /* netns_fd= */ -EBADF,
                        /* userns_fd= */ -EBADF,
                        root_fd,
                        &child);
        if (r < 0)
                goto finish;
        if (r == 0) {
                _cleanup_free_ char *mount_outside_fn = NULL, *mount_inside = NULL;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                _cleanup_close_ int dest_fd = -EBADF;
                _cleanup_free_ char *dest_fn = NULL;
                r = chase(dest, /* root= */ NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME|((flags & MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY) ? CHASE_MKDIR_0755 : 0), &dest_fn, &dest_fd);
                if (r < 0)
                        log_debug_errno(r, "Failed to pin parent directory of mount '%s', ignoring: %m", dest);
                else if (flags & MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY) {
                        r = make_mount_point_inode_from_mode(dest_fd, dest_fn, (flags & MOUNT_IN_NAMESPACE_IS_IMAGE) ? S_IFDIR : chased_src_st->st_mode, 0700);
                        if (r < 0)
                                log_debug_errno(r, "Failed to make mount point inode of mount '%s', ignoring: %m", dest);
                }

                /* Fifth, move the mount to the right place inside */
                r = path_extract_filename(mount_outside, &mount_outside_fn);
                if (r < 0) {
                        log_debug_errno(r, "Failed to extract filename from propagation file or directory '%s': %m", mount_outside);
                        report_errno_and_exit(errno_pipe_fd[1], r);
                }

                mount_inside = path_join(incoming_path, mount_outside_fn);
                if (!mount_inside)
                        report_errno_and_exit(errno_pipe_fd[1], log_oom_debug());

                r = mount_nofollow_verbose(LOG_DEBUG, mount_inside, dest_fd >= 0 ? FORMAT_PROC_FD_PATH(dest_fd) : dest, /* fstype= */ NULL, MS_MOVE, /* options= */ NULL);
                if (r < 0)
                        report_errno_and_exit(errno_pipe_fd[1], r);

                _exit(EXIT_SUCCESS);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = wait_for_terminate_and_check("(sd-bindmnt)", child, 0);
        if (r < 0) {
                log_debug_errno(r, "Failed to wait for child: %m");
                goto finish;
        }
        if (r != EXIT_SUCCESS) {
                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r))
                        log_debug_errno(r, "Failed to mount: %m");
                else
                        log_debug("Child failed.");
                goto finish;
        }

finish:
        if (mount_outside_mounted)
                (void) umount_verbose(LOG_DEBUG, mount_outside, UMOUNT_NOFOLLOW);
        if (mount_outside_created) {
                if ((flags & MOUNT_IN_NAMESPACE_IS_IMAGE) || S_ISDIR(chased_src_st->st_mode))
                        (void) rmdir(mount_outside);
                else
                        (void) unlink(mount_outside);
        }

        if (mount_tmp_mounted)
                (void) umount_verbose(LOG_DEBUG, mount_tmp, UMOUNT_NOFOLLOW);
        if (mount_tmp_created) {
                if ((flags & MOUNT_IN_NAMESPACE_IS_IMAGE) || S_ISDIR(chased_src_st->st_mode))
                        (void) rmdir(mount_tmp);
                else
                        (void) unlink(mount_tmp);
        }

        if (mount_slave_mounted)
                (void) umount_verbose(LOG_DEBUG, mount_slave, UMOUNT_NOFOLLOW);
        if (mount_slave_created)
                (void) rmdir(mount_slave);

        return r;
}

static int mount_in_namespace(
                const PidRef *target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                MountInNamespaceFlags flags,
                const MountOptions *options,
                const ImagePolicy *image_policy) {

        _cleanup_close_ int mntns_fd = -EBADF, root_fd = -EBADF, pidns_fd = -EBADF, chased_src_fd = -EBADF;
        _cleanup_free_ char *chased_src_path = NULL;
        struct stat st;
        int r;

        assert(propagate_path);
        assert(incoming_path);
        assert(src);
        assert(dest);
        assert((flags & MOUNT_IN_NAMESPACE_IS_IMAGE) || (!options && !image_policy));

        if (!pidref_is_set(target))
                return -ESRCH;

        r = pidref_namespace_open(target, &pidns_fd, &mntns_fd, /* ret_netns_fd = */ NULL, /* ret_userns_fd = */ NULL, &root_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to retrieve FDs of the target process' namespace: %m");

        r = is_our_namespace(mntns_fd, NAMESPACE_MOUNT);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine if mount namespaces are equal: %m");
        /* We can't add new mounts at runtime if the process wasn't started in a namespace */
        if (r > 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to activate bind mount in target, not running in a mount namespace.");

        r = chase(src, NULL, 0, &chased_src_path, &chased_src_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to resolve source path '%s': %m", src);
        log_debug("Chased source path '%s': %s", src, chased_src_path);

        if (fstat(chased_src_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat() resolved source path '%s': %m", src);
        if (S_ISLNK(st.st_mode)) /* This shouldn't really happen, given that we just chased the symlinks above, but let's better be safe… */
                return log_debug_errno(SYNTHETIC_ERRNO(ELOOP), "Source path '%s' can't be a symbolic link.", src);

        if (!mount_new_api_supported()) /* Fallback if we can't use the new mount API */
                return mount_in_namespace_legacy(
                                chased_src_path,
                                chased_src_fd,
                                &st,
                                propagate_path,
                                incoming_path,
                                dest,
                                pidns_fd,
                                mntns_fd,
                                root_fd,
                                flags,
                                options,
                                image_policy);

        _cleanup_(dissected_image_unrefp) DissectedImage *img = NULL;
        _cleanup_close_ int new_mount_fd = -EBADF;
        _cleanup_close_pair_ int errno_pipe_fd[2] = EBADF_PAIR;
        pid_t child;

        if (flags & MOUNT_IN_NAMESPACE_IS_IMAGE) {
                r = verity_dissect_and_mount(
                                chased_src_fd,
                                chased_src_path,
                                /* dest= */ NULL,
                                options,
                                image_policy,
                                /* image_filter= */ NULL,
                                /* extension_release_data= */ NULL,
                                /* required_class= */ _IMAGE_CLASS_INVALID,
                                /* verity= */ NULL,
                                &img);
                if (r < 0)
                        return log_debug_errno(r,
                                               "Failed to dissect and mount image '%s': %m",
                                               chased_src_path);
        } else {
                new_mount_fd = open_tree(
                                chased_src_fd,
                                "",
                                OPEN_TREE_CLONE|OPEN_TREE_CLOEXEC|AT_SYMLINK_NOFOLLOW|AT_EMPTY_PATH);
                if (new_mount_fd < 0)
                        return log_debug_errno(
                                        errno,
                                        "Failed to open mount source '%s': %m",
                                        chased_src_path);

                if ((flags & MOUNT_IN_NAMESPACE_READ_ONLY) && mount_setattr(new_mount_fd, "", AT_EMPTY_PATH,
                                               &(struct mount_attr) {
                                                       .attr_set = MOUNT_ATTR_RDONLY,
                                               }, MOUNT_ATTR_SIZE_VER0) < 0)
                        return log_debug_errno(errno,
                                               "Failed to set mount for '%s' to read only: %m",
                                               chased_src_path);
        }

        if (pipe2(errno_pipe_fd, O_CLOEXEC|O_NONBLOCK) < 0)
                return log_debug_errno(errno, "Failed to create pipe: %m");

        r = namespace_fork("(sd-bindmnt)",
                           "(sd-bindmnt-inner)",
                           /* except_fds= */ NULL,
                           /* n_except_fds= */ 0,
                           FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM,
                           pidns_fd,
                           mntns_fd,
                           /* netns_fd= */ -EBADF,
                           /* userns_fd= */ -EBADF,
                           root_fd,
                           &child);
        if (r < 0)
                return log_debug_errno(r, "Failed to fork off mount helper into namespace: %m");
        if (r == 0) {
                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                _cleanup_close_ int dest_fd = -EBADF;
                _cleanup_free_ char *dest_fn = NULL;
                r = chase(dest, /* root= */ NULL, CHASE_PARENT|CHASE_EXTRACT_FILENAME|((flags & MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY) ? CHASE_MKDIR_0755 : 0), &dest_fn, &dest_fd);
                if (r < 0)
                        report_errno_and_exit(errno_pipe_fd[1], r);

                if (flags & MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY)
                        (void) make_mount_point_inode_from_mode(dest_fd, dest_fn, img ? S_IFDIR : st.st_mode, 0700);

                if (img) {
                        DissectImageFlags f =
                                DISSECT_IMAGE_TRY_ATOMIC_MOUNT_EXCHANGE |
                                DISSECT_IMAGE_ALLOW_USERSPACE_VERITY;

                        if (flags & MOUNT_IN_NAMESPACE_MAKE_FILE_OR_DIRECTORY)
                                f |= DISSECT_IMAGE_MKDIR;

                        if (flags & MOUNT_IN_NAMESPACE_READ_ONLY)
                                f |= DISSECT_IMAGE_READ_ONLY;

                        r = dissected_image_mount(
                                        img,
                                        dest,
                                        /* uid_shift= */ UID_INVALID,
                                        /* uid_range= */ UID_INVALID,
                                        /* userns_fd= */ -EBADF,
                                        f);
                } else
                        r = mount_exchange_graceful(new_mount_fd, dest, /* mount_beneath= */ true);

                report_errno_and_exit(errno_pipe_fd[1], r);
        }

        errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

        r = wait_for_terminate_and_check("(sd-bindmnt)", child, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to wait for child: %m");
        if (r != EXIT_SUCCESS) {
                if (read(errno_pipe_fd[0], &r, sizeof(r)) == sizeof(r))
                        return log_debug_errno(r, "Failed to mount into namespace: %m");

                return log_debug_errno(SYNTHETIC_ERRNO(EPROTO), "Child failed.");
        }

        return 0;
}

int bind_mount_in_namespace(
                const PidRef *target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                MountInNamespaceFlags flags) {

        return mount_in_namespace(target,
                                  propagate_path,
                                  incoming_path,
                                  src,
                                  dest,
                                  flags & ~MOUNT_IN_NAMESPACE_IS_IMAGE,
                                  /* options = */ NULL,
                                  /* image_policy = */ NULL);
}

int mount_image_in_namespace(
                const PidRef *target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                MountInNamespaceFlags flags,
                const MountOptions *options,
                const ImagePolicy *image_policy) {

        return mount_in_namespace(target,
                                  propagate_path,
                                  incoming_path,
                                  src,
                                  dest,
                                  flags | MOUNT_IN_NAMESPACE_IS_IMAGE,
                                  options,
                                  image_policy);
}

int make_mount_point(const char *path) {
        int r;

        assert(path);

        /* If 'path' is already a mount point, does nothing and returns 0. If it is not it makes it one, and returns 1. */

        r = path_is_mount_point(path);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine whether '%s' is a mount point: %m", path);
        if (r > 0)
                return 0;

        r = mount_nofollow_verbose(LOG_DEBUG, path, path, NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        return 1;
}

int fd_make_mount_point(int fd) {
        int r;

        assert(fd >= 0);

        r = is_mount_point_at(fd, NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine whether file descriptor is a mount point: %m");
        if (r > 0)
                return 0;

        r = mount_follow_verbose(LOG_DEBUG, FORMAT_PROC_FD_PATH(fd), FORMAT_PROC_FD_PATH(fd), NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        return 1;
}

int make_userns(uid_t uid_shift,
                uid_t uid_range,
                uid_t source_owner,
                uid_t dest_owner,
                RemountIdmapping idmapping) {

        _cleanup_close_ int userns_fd = -EBADF;
        _cleanup_free_ char *line = NULL;
        uid_t source_base = 0;

        /* Allocates a userns file descriptor with the mapping we need. For this we'll fork off a child
         * process whose only purpose is to give us a new user namespace. It's killed when we got it. */

        if (!userns_shift_range_valid(uid_shift, uid_range))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid UID range for user namespace.");

        switch (idmapping) {

        case REMOUNT_IDMAPPING_FOREIGN_WITH_HOST_ROOT:
                source_base = FOREIGN_UID_BASE;
                _fallthrough_;

        case REMOUNT_IDMAPPING_NONE:
        case REMOUNT_IDMAPPING_HOST_ROOT:

                if (asprintf(&line,
                             UID_FMT " " UID_FMT " " UID_FMT "\n",
                             source_base, uid_shift, uid_range) < 0)
                        return log_oom_debug();

                /* If requested we'll include an entry in the mapping so that the host root user can make
                 * changes to the uidmapped mount like it normally would. Specifically, we'll map the user
                 * with UID_MAPPED_ROOT on the backing fs to UID 0. This is useful, since nspawn code wants
                 * to create various missing inodes in the OS tree before booting into it, and this becomes
                 * very easy and straightforward to do if it can just do it under its own regular UID. Note
                 * that in that case the container's runtime uidmap (i.e. the one the container payload
                 * processes run in) will leave this UID unmapped, i.e. if we accidentally leave files owned
                 * by host root in the already uidmapped tree around they'll show up as owned by 'nobody',
                 * which is safe. (Of course, we shouldn't leave such inodes around, but always chown() them
                 * to the container's own UID range, but it's good to have a safety net, in case we
                 * forget it.) */
                if (idmapping == REMOUNT_IDMAPPING_HOST_ROOT)
                        if (strextendf(&line,
                                       UID_FMT " " UID_FMT " " UID_FMT "\n",
                                       UID_MAPPED_ROOT, (uid_t) 0u, (uid_t) 1u) < 0)
                                return log_oom_debug();

                break;

        case REMOUNT_IDMAPPING_HOST_OWNER:
                /* Remap the owner of the bind mounted directory to the root user within the container. This
                 * way every file written by root within the container to the bind-mounted directory will
                 * be owned by the original user from the host. All other users will remain unmapped. */
                if (asprintf(&line,
                             UID_FMT " " UID_FMT " " UID_FMT "\n",
                             source_owner, uid_shift, (uid_t) 1u) < 0)
                        return log_oom_debug();
                break;

        case REMOUNT_IDMAPPING_HOST_OWNER_TO_TARGET_OWNER:
                /* Remap the owner of the bind mounted directory to the owner of the target directory
                 * within the container. This way every file written by target directory owner within the
                 * container to the bind-mounted directory will be owned by the original host user.
                 * All other users will remain unmapped. */
                if (asprintf(&line,
                             UID_FMT " " UID_FMT " " UID_FMT "\n",
                             source_owner, dest_owner, (uid_t) 1u) < 0)
                        return log_oom_debug();
                break;

        default:
                assert_not_reached();
        }

        /* We always assign the same UID and GID ranges */
        userns_fd = userns_acquire(line, line, /* setgroups_deny= */ true);
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to acquire new userns: %m");

        return TAKE_FD(userns_fd);
}

int remount_idmap_fd(
                char **paths,
                int userns_fd,
                uint64_t extra_mount_attr_set) {

        int r;

        assert(userns_fd >= 0);

        /* This remounts all specified paths with the specified userns as idmap. It will do so in the
         * order specified in the strv: the expectation is that the top-level directories are at the
         * beginning, and nested directories in the right, so that the tree can be built correctly from left
         * to right. */

        size_t n = strv_length(paths);
        if (n == 0) /* Nothing to do? */
                return 0;

        int *mount_fds = NULL;
        size_t n_mounts_fds = 0;

        mount_fds = new(int, n);
        if (!mount_fds)
                return log_oom_debug();

        CLEANUP_ARRAY(mount_fds, n_mounts_fds, close_many_and_free);

        for (size_t i = 0; i < n; i++) {
                int mntfd;

                /* Clone the mount point */
                mntfd = mount_fds[n_mounts_fds] = open_tree(-EBADF, paths[i], OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
                if (mount_fds[n_mounts_fds] < 0)
                        return log_debug_errno(errno, "Failed to open tree of mounted filesystem '%s': %m", paths[i]);

                n_mounts_fds++;

                /* Set the user namespace mapping attribute on the cloned mount point */
                if (mount_setattr(mntfd, "", AT_EMPTY_PATH,
                                  &(struct mount_attr) {
                                          .attr_set = MOUNT_ATTR_IDMAP | extra_mount_attr_set,
                                          .userns_fd = userns_fd,
                                  }, sizeof(struct mount_attr)) < 0)
                        return log_debug_errno(errno, "Failed to change bind mount attributes for clone of '%s': %m", paths[i]);
        }

        for (size_t i = n; i > 0; i--) { /* Unmount the paths right-to-left */
                /* Remove the old mount points now that we have a idmapped mounts as replacement for all of them */
                r = umount_verbose(LOG_DEBUG, paths[i-1], UMOUNT_NOFOLLOW);
                if (r < 0)
                        return r;
        }

        for (size_t i = 0; i < n; i++) { /* Mount the replacement mounts left-to-right */
                /* And place the cloned version in its place */
                log_debug("Mounting idmapped fs to '%s'", paths[i]);
                if (move_mount(mount_fds[i], "", -EBADF, paths[i], MOVE_MOUNT_F_EMPTY_PATH) < 0)
                        return log_debug_errno(errno, "Failed to attach UID mapped mount to '%s': %m", paths[i]);
        }

        return 0;
}

int remount_idmap(
                char **p,
                uid_t uid_shift,
                uid_t uid_range,
                uid_t source_owner,
                uid_t dest_owner,
                RemountIdmapping idmapping) {

        _cleanup_close_ int userns_fd = -EBADF;

        userns_fd = make_userns(uid_shift, uid_range, source_owner, dest_owner, idmapping);
        if (userns_fd < 0)
                return userns_fd;

        return remount_idmap_fd(p, userns_fd, /* extra_mount_attr_set= */ 0);
}

static void sub_mount_clear(SubMount *s) {
        assert(s);

        s->path = mfree(s->path);
        s->mount_fd = safe_close(s->mount_fd);
}

void sub_mount_array_free(SubMount *s, size_t n) {
        assert(s || n == 0);

        for (size_t i = 0; i < n; i++)
                sub_mount_clear(s + i);

        free(s);
}

static int sub_mount_compare(const SubMount *a, const SubMount *b) {
        assert(a);
        assert(b);
        assert(a->path);
        assert(b->path);

        return path_compare(a->path, b->path);
}

static void sub_mount_drop(SubMount *s, size_t n) {
        assert(s || n == 0);

        for (size_t m = 0, i = 1; i < n; i++) {
                if (path_startswith(s[i].path, s[m].path))
                        sub_mount_clear(s + i);
                else
                        m = i;
        }
}

int get_sub_mounts(const char *prefix, SubMount **ret_mounts, size_t *ret_n_mounts) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        SubMount *mounts = NULL;
        size_t n = 0;
        int r;

        CLEANUP_ARRAY(mounts, n, sub_mount_array_free);

        assert(prefix);
        assert(ret_mounts);
        assert(ret_n_mounts);

        r = libmount_parse_mountinfo(/* source = */ NULL, &table, &iter);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        for (;;) {
                _cleanup_close_ int mount_fd = -EBADF;
                _cleanup_free_ char *p = NULL;
                struct libmnt_fs *fs;
                const char *path;
                int id1, id2;

                r = mnt_table_next_fs(table, iter, &fs);
                if (r == 1)
                        break; /* EOF */
                if (r < 0)
                        return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                path = mnt_fs_get_target(fs);
                if (!path)
                        continue;

                if (isempty(path_startswith(path, prefix)))
                        continue;

                id1 = mnt_fs_get_id(fs);
                r = path_get_mnt_id(path, &id2);
                if (r < 0) {
                        log_debug_errno(r, "Failed to get mount ID of '%s', ignoring: %m", path);
                        continue;
                }
                if (id1 != id2) {
                        /* The path may be hidden by another over-mount or already remounted. */
                        log_debug("The mount IDs of '%s' obtained by libmount and path_get_mnt_id() are different (%i vs %i), ignoring.",
                                  path, id1, id2);
                        continue;
                }

                mount_fd = open(path, O_CLOEXEC|O_PATH);
                if (mount_fd < 0) {
                        if (errno == ENOENT) /* The path may be hidden by another over-mount or already unmounted. */
                                continue;

                        return log_debug_errno(errno, "Failed to open subtree of mounted filesystem '%s': %m", path);
                }

                p = strdup(path);
                if (!p)
                        return log_oom_debug();

                if (!GREEDY_REALLOC(mounts, n + 1))
                        return log_oom_debug();

                mounts[n++] = (SubMount) {
                        .path = TAKE_PTR(p),
                        .mount_fd = TAKE_FD(mount_fd),
                };
        }

        typesafe_qsort(mounts, n, sub_mount_compare);
        sub_mount_drop(mounts, n);

        *ret_mounts = TAKE_PTR(mounts);
        *ret_n_mounts = n;
        return 0;
}

int bind_mount_submounts(
                const char *source,
                const char *target) {

        SubMount *mounts = NULL;
        size_t n = 0;
        int ret = 0, r;

        /* Bind mounts all child mounts of 'source' to 'target'. Useful when setting up a new procfs instance
         * with new mount options to copy the original submounts over. */

        assert(source);
        assert(target);

        CLEANUP_ARRAY(mounts, n, sub_mount_array_free);

        r = get_sub_mounts(source, &mounts, &n);
        if (r < 0)
                return r;

        FOREACH_ARRAY(m, mounts, n) {
                _cleanup_free_ char *t = NULL;
                const char *suffix;

                if (isempty(m->path))
                        continue;

                assert_se(suffix = path_startswith(m->path, source));

                t = path_join(target, suffix);
                if (!t)
                        return -ENOMEM;

                r = path_is_mount_point(t);
                if (r < 0) {
                        log_debug_errno(r, "Failed to detect if '%s' already is a mount point, ignoring: %m", t);
                        continue;
                }
                if (r > 0) {
                        log_debug("Not bind mounting '%s' from '%s' to '%s', since there's already a mountpoint.", suffix, source, target);
                        continue;
                }

                r = mount_follow_verbose(LOG_DEBUG, FORMAT_PROC_FD_PATH(m->mount_fd), t, NULL, MS_BIND|MS_REC, NULL);
                if (r < 0 && ret == 0)
                        ret = r;
        }

        return ret;
}

int make_mount_point_inode_from_mode(int dir_fd, const char *dest, mode_t source_mode, mode_t target_mode) {
        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);
        assert(dest);

        if (S_ISDIR(source_mode))
                return mkdirat_label(dir_fd, dest, target_mode & 07777);
        else
                return RET_NERRNO(mknodat(dir_fd, dest, S_IFREG|(target_mode & 07666), 0)); /* Mask off X bit */
}

int make_mount_point_inode_from_path(const char *source, const char *dest, mode_t access_mode) {
        struct stat st;

        assert(source);
        assert(dest);

        if (stat(source, &st) < 0)
                return -errno;

        return make_mount_point_inode_from_mode(AT_FDCWD, dest, st.st_mode, access_mode);
}

int trigger_automount_at(int dir_fd, const char *path) {
        _cleanup_free_ char *nested = NULL;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        nested = path_join(path, "a");
        if (!nested)
                return -ENOMEM;

        (void) faccessat(dir_fd, nested, F_OK, 0);

        return 0;
}

unsigned long credentials_fs_mount_flags(bool ro) {
        /* A tight set of mount flags for credentials mounts */
        return MS_NODEV|MS_NOEXEC|MS_NOSUID|ms_nosymfollow_supported()|(ro ? MS_RDONLY : 0);
}

int mount_credentials_fs(const char *path, size_t size, bool ro) {
        _cleanup_free_ char *opts = NULL;
        int r, noswap_supported;

        /* Mounts a file system we can place credentials in, i.e. with tight access modes right from the
         * beginning, and ideally swapping turned off. In order of preference:
         *
         *      1. tmpfs if it supports "noswap"
         *      2. ramfs
         *      3. tmpfs if it doesn't support "noswap"
         */

        noswap_supported = mount_option_supported("tmpfs", "noswap", NULL); /* Check explicitly to avoid kmsg noise */
        if (noswap_supported > 0) {
                _cleanup_free_ char *noswap_opts = NULL;

                if (asprintf(&noswap_opts, "mode=0700,nr_inodes=1024,size=%zu,noswap", size) < 0)
                        return -ENOMEM;

                /* Best case: tmpfs with noswap (needs kernel >= 6.3) */

                r = mount_nofollow_verbose(
                                LOG_DEBUG,
                                "tmpfs",
                                path,
                                "tmpfs",
                                credentials_fs_mount_flags(ro),
                                noswap_opts);
                if (r >= 0)
                        return r;
        }

        r = mount_nofollow_verbose(
                        LOG_DEBUG,
                        "ramfs",
                        path,
                        "ramfs",
                        credentials_fs_mount_flags(ro),
                        "mode=0700");
        if (r >= 0)
                return r;

        if (asprintf(&opts, "mode=0700,nr_inodes=1024,size=%zu", size) < 0)
                return -ENOMEM;

        return mount_nofollow_verbose(
                        LOG_DEBUG,
                        "tmpfs",
                        path,
                        "tmpfs",
                        credentials_fs_mount_flags(ro),
                        opts);
}

int make_fsmount(
                int error_log_level,
                const char *what,
                const char *type,
                unsigned long flags,
                const char *options,
                int userns_fd) {

        _cleanup_close_ int fs_fd = -EBADF, mnt_fd = -EBADF;
        _cleanup_free_ char *o = NULL;
        unsigned long f;
        int r;

        assert(type);
        assert(what);

        r = mount_option_mangle(options, flags, &f, &o);
        if (r < 0)
                return log_full_errno(
                                error_log_level, r, "Failed to mangle mount options %s: %m",
                                strempty(options));

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *fl = NULL;
                (void) mount_flags_to_string(f, &fl);

                log_debug("Creating mount fd for %s (%s) (%s \"%s\")...",
                        strna(what), strna(type), strnull(fl), strempty(o));
        }

        fs_fd = fsopen(type, FSOPEN_CLOEXEC);
        if (fs_fd < 0)
                return log_full_errno(error_log_level, errno, "Failed to open superblock for \"%s\": %m", type);

        if (fsconfig(fs_fd, FSCONFIG_SET_STRING, "source", what, 0) < 0)
                return log_full_errno(error_log_level, errno, "Failed to set mount source for \"%s\" to \"%s\": %m", type, what);

        if (FLAGS_SET(f, MS_RDONLY))
                if (fsconfig(fs_fd, FSCONFIG_SET_FLAG, "ro", NULL, 0) < 0)
                        return log_full_errno(error_log_level, errno, "Failed to set read only mount flag for \"%s\": %m", type);

        for (const char *p = o;;) {
                _cleanup_free_ char *word = NULL;
                char *eq;

                r = extract_first_word(&p, &word, ",", EXTRACT_KEEP_QUOTE);
                if (r < 0)
                        return log_full_errno(error_log_level, r, "Failed to parse mount option string \"%s\": %m", o);
                if (r == 0)
                        break;

                eq = strchr(word, '=');
                if (eq) {
                        *eq = 0;
                        eq++;

                        if (fsconfig(fs_fd, FSCONFIG_SET_STRING, word, eq, 0) < 0)
                                return log_full_errno(error_log_level, errno, "Failed to set mount option \"%s=%s\" for \"%s\": %m", word, eq, type);
                } else {
                        if (fsconfig(fs_fd, FSCONFIG_SET_FLAG, word, NULL, 0) < 0)
                                return log_full_errno(error_log_level, errno, "Failed to set mount flag \"%s\" for \"%s\": %m", word, type);
                }
        }

        if (fsconfig(fs_fd, FSCONFIG_CMD_CREATE, NULL, NULL, 0) < 0)
                return log_full_errno(error_log_level, errno, "Failed to realize fs fd for \"%s\" (\"%s\"): %m", what, type);

        mnt_fd = fsmount(fs_fd, FSMOUNT_CLOEXEC, 0);
        if (mnt_fd < 0)
                return log_full_errno(error_log_level, errno, "Failed to create mount fd for \"%s\" (\"%s\"): %m", what, type);

        struct mount_attr ma = {
                .attr_set = ms_flags_to_mount_attr(f) | (userns_fd >= 0 ? MOUNT_ATTR_IDMAP : 0),
                .userns_fd = userns_fd,
        };
        if (ma.attr_set != 0 && mount_setattr(mnt_fd, "", AT_EMPTY_PATH|AT_RECURSIVE, &ma, MOUNT_ATTR_SIZE_VER0) < 0)
                return log_full_errno(error_log_level,
                                      errno,
                                      "Failed to set mount flags for \"%s\" (\"%s\"): %m",
                                      what,
                                      type);

        return TAKE_FD(mnt_fd);
}

char* umount_and_rmdir_and_free(char *p) {
        if (!p)
                return NULL;

        PROTECT_ERRNO;
        (void) umount_recursive(p, 0);
        (void) rmdir(p);
        return mfree(p);
}

char* umount_and_free(char *p) {
        if (!p)
                return NULL;

        PROTECT_ERRNO;
        (void) umount_recursive(p, 0);
        return mfree(p);
}

char* umount_and_unlink_and_free(char *p) {
        if (!p)
                return NULL;

        PROTECT_ERRNO;
        (void) umount2(p, 0);
        (void) unlink(p);
        return mfree(p);
}

int path_get_mount_info_at(
                int dir_fd,
                const char *path,
                char **ret_fstype,
                char **ret_options,
                char **ret_source) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
        int r, mnt_id;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        r = path_get_mnt_id_at(dir_fd, path, &mnt_id);
        if (r < 0)
                return log_debug_errno(r, "Failed to get mount ID: %m");

        /* When getting options is requested, we also need to parse utab, otherwise userspace options like
         * "_netdev" will be lost. */
        if (ret_options)
                r = libmount_parse_with_utab(&table, &iter);
        else
                r = libmount_parse_mountinfo(/* source = */ NULL, &table, &iter);
        if (r < 0)
                return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

        for (;;) {
                struct libmnt_fs *fs;

                r = mnt_table_next_fs(table, iter, &fs);
                if (r == 1)
                        break; /* EOF */
                if (r < 0)
                        return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                if (mnt_fs_get_id(fs) != mnt_id)
                        continue;

                _cleanup_free_ char *fstype = NULL, *options = NULL, *source = NULL;

                if (ret_fstype) {
                        fstype = strdup(strempty(mnt_fs_get_fstype(fs)));
                        if (!fstype)
                                return log_oom_debug();
                }

                if (ret_options) {
                        options = strdup(strempty(mnt_fs_get_options(fs)));
                        if (!options)
                                return log_oom_debug();
                }

                if (ret_source) {
                        source = strdup(strempty(mnt_fs_get_source(fs)));
                        if (!source)
                                return log_oom_debug();
                }

                if (ret_fstype)
                        *ret_fstype = TAKE_PTR(fstype);
                if (ret_options)
                        *ret_options = TAKE_PTR(options);
                if (ret_source)
                        *ret_source = TAKE_PTR(source);

                return 0;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(ESTALE), "Cannot find mount ID %i from /proc/self/mountinfo.", mnt_id);
}

int path_is_network_fs_harder_at(int dir_fd, const char *path) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        assert(dir_fd >= 0 || dir_fd == AT_FDCWD);

        fd = xopenat(dir_fd, path, O_PATH | O_CLOEXEC | O_NOFOLLOW);
        if (fd < 0)
                return fd;

        r = fd_is_network_fs(fd);
        if (r != 0)
                return r;

        _cleanup_free_ char *fstype = NULL, *options = NULL;
        r = path_get_mount_info_at(fd, /* path = */ NULL, &fstype, &options, /* ret_source = */ NULL);
        if (r < 0)
                return r;

        if (fstype_is_network(fstype))
                return true;

        if (fstab_test_option(options, "_netdev\0"))
                return true;

        return false;
}
