/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>
#include <linux/loop.h>
#include <linux/fs.h>

#include "alloc-util.h"
#include "chase-symlinks.h"
#include "dissect-image.h"
#include "exec-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "label.h"
#include "libmount-util.h"
#include "missing_mount.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "set.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "user-util.h"

int mount_fd(const char *source,
             int target_fd,
             const char *filesystemtype,
             unsigned long mountflags,
             const void *data) {

        if (mount(source, FORMAT_PROC_FD_PATH(target_fd), filesystemtype, mountflags, data) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* ENOENT can mean two things: either that the source is missing, or that /proc/ isn't
                 * mounted. Check for the latter to generate better error messages. */
                if (proc_mounted() == 0)
                        return -ENOSYS;

                return -ENOENT;
        }

        return 0;
}

int mount_nofollow(
                const char *source,
                const char *target,
                const char *filesystemtype,
                unsigned long mountflags,
                const void *data) {

        _cleanup_close_ int fd = -1;

        /* In almost all cases we want to manipulate the mount table without following symlinks, hence
         * mount_nofollow() is usually the way to go. The only exceptions are environments where /proc/ is
         * not available yet, since we need /proc/self/fd/ for this logic to work. i.e. during the early
         * initialization of namespacing/container stuff where /proc is not yet mounted (and maybe even the
         * fs to mount) we can only use traditional mount() directly.
         *
         * Note that this disables following only for the final component of the target, i.e symlinks within
         * the path of the target are honoured, as are symlinks in the source path everywhere. */

        fd = open(target, O_PATH|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        return mount_fd(source, fd, filesystemtype, mountflags, data);
}

int umount_recursive(const char *prefix, int flags) {
        int n = 0, r;
        bool again;

        /* Try to umount everything recursively below a directory. Also, take care of stacked mounts, and
         * keep unmounting them until they are gone. */

        do {
                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;

                again = false;

                r = libmount_parse("/proc/self/mountinfo", NULL, &table, &iter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

                for (;;) {
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

                        if (!path_startswith(path, prefix))
                                continue;

                        if (umount2(path, flags | UMOUNT_NOFOLLOW) < 0) {
                                log_debug_errno(errno, "Failed to umount %s, ignoring: %m", path);
                                continue;
                        }

                        log_debug("Successfully unmounted %s", path);

                        again = true;
                        n++;

                        break;
                }
        } while (again);

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

                r = libmount_parse("/proc/self/mountinfo", proc_self_mountinfo, &table, &iter);
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
                                char **i;

                                STRV_FOREACH(i, deny_list) {
                                        if (path_equal(*i, prefix))
                                                continue;

                                        if (!path_startswith(*i, prefix))
                                                continue;

                                        if (path_startswith(path, *i)) {
                                                deny_listed = true;
                                                log_debug("Not remounting %s deny-listed by %s, called for %s", path, *i, prefix);
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

                                q = path_is_mount_point(x, NULL, 0);
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

                        log_debug("Remounted %s.", x);
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
                if (laccess(path, F_OK) < 0) /* Hmm, it's not in the mount table, but does it exist at all? */
                        return -errno;

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

int mount_move_root(const char *path) {
        assert(path);

        if (chdir(path) < 0)
                return -errno;

        if (mount(path, "/", NULL, MS_MOVE, NULL) < 0)
                return -errno;

        if (chroot(".") < 0)
                return -errno;

        return RET_NERRNO(chdir("/"));
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
        const char *node = NULL;

        assert(ret);

        if (!runtime_dir)
                runtime_dir = "/run";

        switch(mode & S_IFMT) {
                case S_IFREG:
                        node = "/systemd/inaccessible/reg";
                        break;

                case S_IFDIR:
                        node = "/systemd/inaccessible/dir";
                        break;

                case S_IFCHR:
                        node = "/systemd/inaccessible/chr";
                        break;

                case S_IFBLK:
                        node = "/systemd/inaccessible/blk";
                        break;

                case S_IFIFO:
                        node = "/systemd/inaccessible/fifo";
                        break;

                case S_IFSOCK:
                        node = "/systemd/inaccessible/sock";
                        break;
        }
        if (!node)
                return -EINVAL;

        d = path_join(runtime_dir, node);
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

int mount_flags_to_string(long unsigned flags, char **ret) {
        static const struct {
                long unsigned flag;
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

        for (size_t i = 0; i < ELEMENTSOF(map); i++)
                if (flags & map[i].flag) {
                        if (!strextend_with_separator(&str, "|", map[i].name))
                                return -ENOMEM;
                        flags &= ~map[i].flag;
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

        if ((f & MS_REMOUNT) && !what && !type)
                log_debug("Remounting %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if (!what && !type)
                log_debug("Mounting %s (%s \"%s\")...",
                          where, strnull(fl), strempty(o));
        else if ((f & MS_BIND) && !type)
                log_debug("Bind-mounting %s on %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
        else if (f & MS_MOVE)
                log_debug("Moving mount %s → %s (%s \"%s\")...",
                          what, where, strnull(fl), strempty(o));
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
                const char *what,
                int flags) {

        assert(what);

        log_debug("Umounting %s...", what);

        if (umount2(what, flags) < 0)
                return log_full_errno(error_log_level, errno,
                                      "Failed to unmount %s: %m", what);

        return 0;
}

int mount_option_mangle(
                const char *options,
                unsigned long mount_flags,
                unsigned long *ret_mount_flags,
                char **ret_remaining_options) {

        const struct libmnt_optmap *map;
        _cleanup_free_ char *ret = NULL;
        int r;

        /* This extracts mount flags from the mount options, and store
         * non-mount-flag options to '*ret_remaining_options'.
         * E.g.,
         * "rw,nosuid,nodev,relatime,size=1630748k,mode=700,uid=1000,gid=1000"
         * is split to MS_NOSUID|MS_NODEV|MS_RELATIME and
         * "size=1630748k,mode=700,uid=1000,gid=1000".
         * See more examples in test-mount-utils.c.
         *
         * Note that if 'options' does not contain any non-mount-flag options,
         * then '*ret_remaining_options' is set to NULL instead of empty string.
         * Note that this does not check validity of options stored in
         * '*ret_remaining_options'.
         * Note that if 'options' is NULL, then this just copies 'mount_flags'
         * to '*ret_mount_flags'. */

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
                        else if (mount_flags & ent->id)
                                mount_flags ^= ent->id;

                        break;
                }

                /* If 'word' is not a mount flag, then store it in '*ret_remaining_options'. */
                if (!ent->name && !strextend_with_separator(&ret, ",", word))
                        return -ENOMEM;
        }

        *ret_mount_flags = mount_flags;
        *ret_remaining_options = TAKE_PTR(ret);

        return 0;
}

static int mount_in_namespace(
                pid_t target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                bool read_only,
                bool make_file_or_directory,
                const MountOptions *options,
                bool is_image) {

        _cleanup_close_pair_ int errno_pipe_fd[2] = { -1, -1 };
        _cleanup_close_ int self_mntns_fd = -1, mntns_fd = -1, root_fd = -1, pidns_fd = -1, chased_src_fd = -1;
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p;
        bool mount_slave_created = false, mount_slave_mounted = false,
                mount_tmp_created = false, mount_tmp_mounted = false,
                mount_outside_created = false, mount_outside_mounted = false;
        struct stat st, self_mntns_st;
        pid_t child;
        int r;

        assert(target > 0);
        assert(propagate_path);
        assert(incoming_path);
        assert(src);
        assert(dest);
        assert(!options || is_image);

        r = namespace_open(target, &pidns_fd, &mntns_fd, NULL, NULL, &root_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to retrieve FDs of the target process' namespace: %m");

        if (fstat(mntns_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to fstat mount namespace FD of target process: %m");

        r = namespace_open(0, NULL, &self_mntns_fd, NULL, NULL, NULL);
        if (r < 0)
                return log_debug_errno(r, "Failed to retrieve FDs of systemd's namespace: %m");

        if (fstat(self_mntns_fd, &self_mntns_st) < 0)
                return log_debug_errno(errno, "Failed to fstat mount namespace FD of systemd: %m");

        /* We can't add new mounts at runtime if the process wasn't started in a namespace */
        if (st.st_ino == self_mntns_st.st_ino && st.st_dev == self_mntns_st.st_dev)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "Failed to activate bind mount in target, not running in a mount namespace");

        /* One day, when bind mounting /proc/self/fd/n works across namespace boundaries we should rework
         * this logic to make use of it... */

        p = strjoina(propagate_path, "/");
        r = laccess(p, F_OK);
        if (r < 0)
                return log_debug_errno(r == -ENOENT ? SYNTHETIC_ERRNO(EOPNOTSUPP) : r, "Target does not allow propagation of mount points");

        r = chase_symlinks(src, NULL, CHASE_TRAIL_SLASH, NULL, &chased_src_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to resolve source path of %s: %m", src);

        if (fstat(chased_src_fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat() resolved source path %s: %m", src);
        if (S_ISLNK(st.st_mode)) /* This shouldn't really happen, given that we just chased the symlinks above, but let's better be safe… */
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Source directory %s can't be a symbolic link", src);

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
        if (is_image)
                r = mkdir_p(mount_tmp, 0700);
        else
                r = make_mount_point_inode_from_stat(&st, mount_tmp, 0700);
        if (r < 0) {
                log_debug_errno(r, "Failed to create temporary mount point %s: %m", mount_tmp);
                goto finish;
        }

        mount_tmp_created = true;

        if (is_image)
                r = verity_dissect_and_mount(FORMAT_PROC_FD_PATH(chased_src_fd), mount_tmp, options, NULL, NULL, NULL);
        else
                r = mount_follow_verbose(LOG_DEBUG, FORMAT_PROC_FD_PATH(chased_src_fd), mount_tmp, NULL, MS_BIND, NULL);
        if (r < 0)
                goto finish;

        mount_tmp_mounted = true;

        /* Third, we remount the new bind mount read-only if requested. */
        if (read_only) {
                r = mount_nofollow_verbose(LOG_DEBUG, NULL, mount_tmp, NULL, MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
                if (r < 0)
                        goto finish;
        }

        /* Fourth, we move the new bind mount into the propagation directory. This way it will appear there read-only
         * right-away. */

        mount_outside = strjoina(propagate_path, "/XXXXXX");
        if (is_image || S_ISDIR(st.st_mode))
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

        if (is_image || S_ISDIR(st.st_mode))
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

        r = namespace_fork("(sd-bindmnt)", "(sd-bindmnt-inner)", NULL, 0, FORK_RESET_SIGNALS|FORK_DEATHSIG,
                           pidns_fd, mntns_fd, -1, -1, root_fd, &child);
        if (r < 0)
                goto finish;
        if (r == 0) {
                const char *mount_inside;

                errno_pipe_fd[0] = safe_close(errno_pipe_fd[0]);

                if (make_file_or_directory) {
                        if (!is_image) {
                                (void) mkdir_parents(dest, 0755);
                                (void) make_mount_point_inode_from_stat(&st, dest, 0700);
                        } else
                                (void) mkdir_p(dest, 0755);
                }

                /* Fifth, move the mount to the right place inside */
                mount_inside = strjoina(incoming_path, basename(mount_outside));
                r = mount_nofollow_verbose(LOG_ERR, mount_inside, dest, NULL, MS_MOVE, NULL);
                if (r < 0)
                        goto child_fail;

                _exit(EXIT_SUCCESS);

        child_fail:
                (void) write(errno_pipe_fd[1], &r, sizeof(r));
                errno_pipe_fd[1] = safe_close(errno_pipe_fd[1]);

                _exit(EXIT_FAILURE);
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
                if (is_image || S_ISDIR(st.st_mode))
                        (void) rmdir(mount_outside);
                else
                        (void) unlink(mount_outside);
        }

        if (mount_tmp_mounted)
                (void) umount_verbose(LOG_DEBUG, mount_tmp, UMOUNT_NOFOLLOW);
        if (mount_tmp_created) {
                if (is_image || S_ISDIR(st.st_mode))
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

int bind_mount_in_namespace(
                pid_t target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                bool read_only,
                bool make_file_or_directory) {

        return mount_in_namespace(target, propagate_path, incoming_path, src, dest, read_only, make_file_or_directory, NULL, false);
}

int mount_image_in_namespace(
                pid_t target,
                const char *propagate_path,
                const char *incoming_path,
                const char *src,
                const char *dest,
                bool read_only,
                bool make_file_or_directory,
                const MountOptions *options) {

        return mount_in_namespace(target, propagate_path, incoming_path, src, dest, read_only, make_file_or_directory, options, true);
}

int make_mount_point(const char *path) {
        int r;

        assert(path);

        /* If 'path' is already a mount point, does nothing and returns 0. If it is not it makes it one, and returns 1. */

        r = path_is_mount_point(path, NULL, 0);
        if (r < 0)
                return log_debug_errno(r, "Failed to determine whether '%s' is a mount point: %m", path);
        if (r > 0)
                return 0;

        r = mount_nofollow_verbose(LOG_DEBUG, path, path, NULL, MS_BIND|MS_REC, NULL);
        if (r < 0)
                return r;

        return 1;
}

static int make_userns(uid_t uid_shift, uid_t uid_range) {
        char line[DECIMAL_STR_MAX(uid_t)*3+3+1];
        _cleanup_close_ int userns_fd = -1;

        /* Allocates a userns file descriptor with the mapping we need. For this we'll fork off a child
         * process whose only purpose is to give us a new user namespace. It's killed when we got it. */

        xsprintf(line, UID_FMT " " UID_FMT " " UID_FMT "\n", 0, uid_shift, uid_range);

        /* We always assign the same UID and GID ranges */
        userns_fd = userns_acquire(line, line);
        if (userns_fd < 0)
                return log_debug_errno(userns_fd, "Failed to acquire new userns: %m");

        return TAKE_FD(userns_fd);
}

int remount_idmap(
                const char *p,
                uid_t uid_shift,
                uid_t uid_range) {

        _cleanup_close_ int mount_fd = -1, userns_fd = -1;
        int r;

        assert(p);

        if (!userns_shift_range_valid(uid_shift, uid_range))
                return -EINVAL;

        /* Clone the mount point */
        mount_fd = open_tree(-1, p, OPEN_TREE_CLONE | OPEN_TREE_CLOEXEC);
        if (mount_fd < 0)
                return log_debug_errno(errno, "Failed to open tree of mounted filesystem '%s': %m", p);

        /* Create a user namespace mapping */
        userns_fd = make_userns(uid_shift, uid_range);
        if (userns_fd < 0)
                return userns_fd;

        /* Set the user namespace mapping attribute on the cloned mount point */
        if (mount_setattr(mount_fd, "", AT_EMPTY_PATH | AT_RECURSIVE,
                          &(struct mount_attr) {
                                  .attr_set = MOUNT_ATTR_IDMAP,
                                  .userns_fd = userns_fd,
                          }, sizeof(struct mount_attr)) < 0)
                return log_debug_errno(errno, "Failed to change bind mount attributes for '%s': %m", p);

        /* Remove the old mount point */
        r = umount_verbose(LOG_DEBUG, p, UMOUNT_NOFOLLOW);
        if (r < 0)
                return r;

        /* And place the cloned version in its place */
        if (move_mount(mount_fd, "", -1, p, MOVE_MOUNT_F_EMPTY_PATH) < 0)
                return log_debug_errno(errno, "Failed to attach UID mapped mount to '%s': %m", p);

        return 0;
}

int make_mount_point_inode_from_stat(const struct stat *st, const char *dest, mode_t mode) {
        assert(st);
        assert(dest);

        if (S_ISDIR(st->st_mode))
                return mkdir_label(dest, mode);
        else
                return mknod(dest, S_IFREG|(mode & ~0111), 0);
}

int make_mount_point_inode_from_path(const char *source, const char *dest, mode_t mode) {
        struct stat st;

        assert(source);
        assert(dest);

        if (stat(source, &st) < 0)
                return -errno;

        return make_mount_point_inode_from_stat(&st, dest, mode);
}
