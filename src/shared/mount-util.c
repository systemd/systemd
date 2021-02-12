/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <linux/loop.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dissect-image.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "libmount-util.h"
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

        char path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];

        xsprintf(path, "/proc/self/fd/%i", target_fd);
        if (mount(source, path, filesystemtype, mountflags, data) < 0) {
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

        /* Try to umount everything recursively below a
         * directory. Also, take care of stacked mounts, and keep
         * unmounting them until they are gone. */

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

static int get_mount_flags(
                struct libmnt_table *table,
                const char *path,
                unsigned long *ret) {

        _cleanup_close_ int fd = -1;
        struct libmnt_fs *fs;
        struct statvfs buf;
        const char *opts;
        int r;

        /* Get the mount flags for the mountpoint at "path" from "table". We have a fallback using statvfs()
         * in place (which provides us with mostly the same info), but it's just a fallback, since using it
         * means triggering autofs or NFS mounts, which we'd rather avoid needlessly.
         *
         * This generally doesn't follow symlinks. */

        fs = mnt_table_find_target(table, path, MNT_ITER_FORWARD);
        if (!fs) {
                log_debug("Could not find '%s' in mount table, ignoring.", path);
                goto fallback;
        }

        opts = mnt_fs_get_vfs_options(fs);
        if (!opts) {
                *ret = 0;
                return 0;
        }

        r = mnt_optstr_get_flags(opts, ret, mnt_get_builtin_optmap(MNT_LINUX_MAP));
        if (r != 0) {
                log_debug_errno(r, "Could not get flags for '%s', ignoring: %m", path);
                goto fallback;
        }

        /* MS_RELATIME is default and trying to set it in an unprivileged container causes EPERM */
        *ret &= ~MS_RELATIME;
        return 0;

fallback:
        fd = open(path, O_PATH|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0)
                return -errno;

        if (fstatvfs(fd, &buf) < 0)
                return -errno;

        /* The statvfs() flags and the mount flags mostly have the same values, but for some cases do
         * not. Hence map the flags manually. (Strictly speaking, ST_RELATIME/MS_RELATIME is the most
         * prominent one that doesn't match, but that's the one we mask away anyway, see above.) */

        *ret =
                FLAGS_SET(buf.f_flag, ST_RDONLY) * MS_RDONLY |
                FLAGS_SET(buf.f_flag, ST_NODEV) * MS_NODEV |
                FLAGS_SET(buf.f_flag, ST_NOEXEC) * MS_NOEXEC |
                FLAGS_SET(buf.f_flag, ST_NOSUID) * MS_NOSUID |
                FLAGS_SET(buf.f_flag, ST_NOATIME) * MS_NOATIME |
                FLAGS_SET(buf.f_flag, ST_NODIRATIME) * MS_NODIRATIME;

        return 0;
}

/* Use this function only if you do not have direct access to /proc/self/mountinfo but the caller can open it
 * for you. This is the case when /proc is masked or not mounted. Otherwise, use bind_remount_recursive. */
int bind_remount_recursive_with_mountinfo(
                const char *prefix,
                unsigned long new_flags,
                unsigned long flags_mask,
                char **deny_list,
                FILE *proc_self_mountinfo) {

        _cleanup_set_free_free_ Set *done = NULL;
        _cleanup_free_ char *simplified = NULL;
        int r;

        assert(prefix);
        assert(proc_self_mountinfo);

        /* Recursively remount a directory (and all its submounts) with desired flags (MS_READONLY,
         * MS_NOSUID, MS_NOEXEC). If the directory is already mounted, we reuse the mount and simply mark it
         * MS_BIND|MS_RDONLY (or remove the MS_RDONLY for read-write operation), ditto for other flags. If it
         * isn't we first make it one. Afterwards we apply (or remove) the flags to all submounts we can
         * access, too. When mounts are stacked on the same mount point we only care for each individual
         * "top-level" mount on each point, as we cannot influence/access the underlying mounts anyway. We do
         * not have any effect on future submounts that might get propagated, they might be writable
         * etc. This includes future submounts that have been triggered via autofs.
         *
         * If the "deny_list" parameter is specified it may contain a list of subtrees to exclude from the
         * remount operation. Note that we'll ignore the deny list for the top-level path. */

        simplified = strdup(prefix);
        if (!simplified)
                return -ENOMEM;

        path_simplify(simplified, false);

        done = set_new(&path_hash_ops);
        if (!done)
                return -ENOMEM;

        for (;;) {
                _cleanup_set_free_free_ Set *todo = NULL;
                _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
                _cleanup_(mnt_free_iterp) struct libmnt_iter *iter = NULL;
                bool top_autofs = false;
                char *x;
                unsigned long orig_flags;

                todo = set_new(&path_hash_ops);
                if (!todo)
                        return -ENOMEM;

                rewind(proc_self_mountinfo);

                r = libmount_parse("/proc/self/mountinfo", proc_self_mountinfo, &table, &iter);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse /proc/self/mountinfo: %m");

                for (;;) {
                        struct libmnt_fs *fs;
                        const char *path, *type;

                        r = mnt_table_next_fs(table, iter, &fs);
                        if (r == 1)
                                break;
                        if (r < 0)
                                return log_debug_errno(r, "Failed to get next entry from /proc/self/mountinfo: %m");

                        path = mnt_fs_get_target(fs);
                        type = mnt_fs_get_fstype(fs);
                        if (!path || !type)
                                continue;

                        if (!path_startswith(path, simplified))
                                continue;

                        /* Ignore this mount if it is deny-listed, but only if it isn't the top-level mount
                         * we shall operate on. */
                        if (!path_equal(path, simplified)) {
                                bool deny_listed = false;
                                char **i;

                                STRV_FOREACH(i, deny_list) {
                                        if (path_equal(*i, simplified))
                                                continue;

                                        if (!path_startswith(*i, simplified))
                                                continue;

                                        if (path_startswith(path, *i)) {
                                                deny_listed = true;
                                                log_debug("Not remounting %s deny-listed by %s, called for %s",
                                                          path, *i, simplified);
                                                break;
                                        }
                                }
                                if (deny_listed)
                                        continue;
                        }

                        /* Let's ignore autofs mounts.  If they aren't
                         * triggered yet, we want to avoid triggering
                         * them, as we don't make any guarantees for
                         * future submounts anyway.  If they are
                         * already triggered, then we will find
                         * another entry for this. */
                        if (streq(type, "autofs")) {
                                top_autofs = top_autofs || path_equal(path, simplified);
                                continue;
                        }

                        if (!set_contains(done, path)) {
                                r = set_put_strdup(&todo, path);
                                if (r < 0)
                                        return r;
                        }
                }

                /* If we have no submounts to process anymore and if
                 * the root is either already done, or an autofs, we
                 * are done */
                if (set_isempty(todo) &&
                    (top_autofs || set_contains(done, simplified)))
                        return 0;

                if (!set_contains(done, simplified) &&
                    !set_contains(todo, simplified)) {
                        /* The prefix directory itself is not yet a mount, make it one. */
                        r = mount_nofollow(simplified, simplified, NULL, MS_BIND|MS_REC, NULL);
                        if (r < 0)
                                return r;

                        orig_flags = 0;
                        (void) get_mount_flags(table, simplified, &orig_flags);

                        r = mount_nofollow(NULL, simplified, NULL, (orig_flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags, NULL);
                        if (r < 0)
                                return r;

                        log_debug("Made top-level directory %s a mount point.", prefix);

                        r = set_put_strdup(&done, simplified);
                        if (r < 0)
                                return r;
                }

                while ((x = set_steal_first(todo))) {

                        r = set_consume(done, x);
                        if (IN_SET(r, 0, -EEXIST))
                                continue;
                        if (r < 0)
                                return r;

                        /* Deal with mount points that are obstructed by a later mount */
                        r = path_is_mount_point(x, NULL, 0);
                        if (IN_SET(r, 0, -ENOENT))
                                continue;
                        if (r < 0) {
                                if (!ERRNO_IS_PRIVILEGE(r))
                                        return r;

                                /* Even if root user invoke this, submounts under private FUSE or NFS mount points
                                 * may not be acceessed. E.g.,
                                 *
                                 * $ bindfs --no-allow-other ~/mnt/mnt ~/mnt/mnt
                                 * $ bindfs --no-allow-other ~/mnt ~/mnt
                                 *
                                 * Then, root user cannot access the mount point ~/mnt/mnt.
                                 * In such cases, the submounts are ignored, as we have no way to manage them. */
                                log_debug_errno(r, "Failed to determine '%s' is mount point or not, ignoring: %m", x);
                                continue;
                        }

                        /* Try to reuse the original flag set */
                        orig_flags = 0;
                        (void) get_mount_flags(table, x, &orig_flags);

                        r = mount_nofollow(NULL, x, NULL, (orig_flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags, NULL);
                        if (r < 0)
                                return r;

                        log_debug("Remounted %s read-only.", x);
                }
        }
}

int bind_remount_recursive(
                const char *prefix,
                unsigned long new_flags,
                unsigned long flags_mask,
                char **deny_list) {

        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;
        int r;

        r = fopen_unlocked("/proc/self/mountinfo", "re", &proc_self_mountinfo);
        if (r < 0)
                return r;

        return bind_remount_recursive_with_mountinfo(prefix, new_flags, flags_mask, deny_list, proc_self_mountinfo);
}

int bind_remount_one_with_mountinfo(
                const char *path,
                unsigned long new_flags,
                unsigned long flags_mask,
                FILE *proc_self_mountinfo) {

        _cleanup_(mnt_free_tablep) struct libmnt_table *table = NULL;
        unsigned long orig_flags = 0;
        int r;

        assert(path);
        assert(proc_self_mountinfo);

        rewind(proc_self_mountinfo);

        table = mnt_new_table();
        if (!table)
                return -ENOMEM;

        r = mnt_table_parse_stream(table, proc_self_mountinfo, "/proc/self/mountinfo");
        if (r < 0)
                return r;

        /* Try to reuse the original flag set */
        (void) get_mount_flags(table, path, &orig_flags);

        r = mount_nofollow(NULL, path, NULL, (orig_flags & ~flags_mask)|MS_BIND|MS_REMOUNT|new_flags, NULL);
        if (r < 0)
                return r;

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

        if (chdir("/") < 0)
                return -errno;

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

#define FLAG(name) (flags & name ? STRINGIFY(name) "|" : "")
static char* mount_flags_to_string(long unsigned flags) {
        char *x;
        _cleanup_free_ char *y = NULL;
        long unsigned overflow;

        overflow = flags & ~(MS_RDONLY |
                             MS_NOSUID |
                             MS_NODEV |
                             MS_NOEXEC |
                             MS_SYNCHRONOUS |
                             MS_REMOUNT |
                             MS_MANDLOCK |
                             MS_DIRSYNC |
                             MS_NOATIME |
                             MS_NODIRATIME |
                             MS_BIND |
                             MS_MOVE |
                             MS_REC |
                             MS_SILENT |
                             MS_POSIXACL |
                             MS_UNBINDABLE |
                             MS_PRIVATE |
                             MS_SLAVE |
                             MS_SHARED |
                             MS_RELATIME |
                             MS_KERNMOUNT |
                             MS_I_VERSION |
                             MS_STRICTATIME |
                             MS_LAZYTIME);

        if (flags == 0 || overflow != 0)
                if (asprintf(&y, "%lx", overflow) < 0)
                        return NULL;

        x = strjoin(FLAG(MS_RDONLY),
                    FLAG(MS_NOSUID),
                    FLAG(MS_NODEV),
                    FLAG(MS_NOEXEC),
                    FLAG(MS_SYNCHRONOUS),
                    FLAG(MS_REMOUNT),
                    FLAG(MS_MANDLOCK),
                    FLAG(MS_DIRSYNC),
                    FLAG(MS_NOATIME),
                    FLAG(MS_NODIRATIME),
                    FLAG(MS_BIND),
                    FLAG(MS_MOVE),
                    FLAG(MS_REC),
                    FLAG(MS_SILENT),
                    FLAG(MS_POSIXACL),
                    FLAG(MS_UNBINDABLE),
                    FLAG(MS_PRIVATE),
                    FLAG(MS_SLAVE),
                    FLAG(MS_SHARED),
                    FLAG(MS_RELATIME),
                    FLAG(MS_KERNMOUNT),
                    FLAG(MS_I_VERSION),
                    FLAG(MS_STRICTATIME),
                    FLAG(MS_LAZYTIME),
                    y);
        if (!x)
                return NULL;
        if (!y)
                x[strlen(x) - 1] = '\0'; /* truncate the last | */
        return x;
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

        fl = mount_flags_to_string(f);

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
                r = mount(what, where, type, f, o) < 0 ? -errno : 0;
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
        const char *p;
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

        p = options;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const struct libmnt_optmap *ent;

                r = extract_first_word(&p, &word, ",", EXTRACT_UNQUOTE);
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
        char mount_slave[] = "/tmp/propagate.XXXXXX", *mount_tmp, *mount_outside, *p,
                chased_src[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
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

        /* One day, when bind mounting /proc/self/fd/n works across
         * namespace boundaries we should rework this logic to make
         * use of it... */

        p = strjoina(propagate_path, "/");
        r = laccess(p, F_OK);
        if (r < 0)
                return log_debug_errno(r == -ENOENT ? SYNTHETIC_ERRNO(EOPNOTSUPP) : r, "Target does not allow propagation of mount points");

        r = chase_symlinks(src, NULL, CHASE_TRAIL_SLASH, NULL, &chased_src_fd);
        if (r < 0)
                return log_debug_errno(r, "Failed to resolve source path of %s: %m", src);
        xsprintf(chased_src, "/proc/self/fd/%i", chased_src_fd);

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
                r = verity_dissect_and_mount(chased_src, mount_tmp, options, NULL, NULL, NULL);
        else
                r = mount_follow_verbose(LOG_DEBUG, chased_src, mount_tmp, NULL, MS_BIND, NULL);
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
