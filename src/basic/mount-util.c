/* SPDX-License-Identifier: LGPL-2.1+ */

#include <errno.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

/* Include later */
#include <libmount.h>

#include "alloc-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "mount-util.h"
#include "mountpoint-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "set.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"

int umount_recursive(const char *prefix, int flags) {
        bool again;
        int n = 0, r;

        /* Try to umount everything recursively below a
         * directory. Also, take care of stacked mounts, and keep
         * unmounting them until they are gone. */

        do {
                _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

                again = false;
                r = 0;

                proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
                if (!proc_self_mountinfo)
                        return -errno;

                (void) __fsetlocking(proc_self_mountinfo, FSETLOCKING_BYCALLER);

                for (;;) {
                        _cleanup_free_ char *path = NULL, *p = NULL;
                        int k;

                        k = fscanf(proc_self_mountinfo,
                                   "%*s "       /* (1) mount id */
                                   "%*s "       /* (2) parent id */
                                   "%*s "       /* (3) major:minor */
                                   "%*s "       /* (4) root */
                                   "%ms "       /* (5) mount point */
                                   "%*s"        /* (6) mount options */
                                   "%*[^-]"     /* (7) optional fields */
                                   "- "         /* (8) separator */
                                   "%*s "       /* (9) file system type */
                                   "%*s"        /* (10) mount source */
                                   "%*s"        /* (11) mount options 2 */
                                   "%*[^\n]",   /* some rubbish at the end */
                                   &path);
                        if (k != 1) {
                                if (k == EOF)
                                        break;

                                continue;
                        }

                        r = cunescape(path, UNESCAPE_RELAX, &p);
                        if (r < 0)
                                return r;

                        if (!path_startswith(p, prefix))
                                continue;

                        if (umount2(p, flags) < 0) {
                                r = log_debug_errno(errno, "Failed to umount %s: %m", p);
                                continue;
                        }

                        log_debug("Successfully unmounted %s", p);

                        again = true;
                        n++;

                        break;
                }

        } while (again);

        return r ? r : n;
}

static int get_mount_flags(const char *path, unsigned long *flags) {
        struct statvfs buf;

        if (statvfs(path, &buf) < 0)
                return -errno;
        *flags = buf.f_flag;
        return 0;
}

/* Use this function only if do you have direct access to /proc/self/mountinfo
 * and need the caller to open it for you. This is the case when /proc is
 * masked or not mounted. Otherwise, use bind_remount_recursive. */
int bind_remount_recursive_with_mountinfo(const char *prefix, bool ro, char **blacklist, FILE *proc_self_mountinfo) {
        _cleanup_set_free_free_ Set *done = NULL;
        _cleanup_free_ char *cleaned = NULL;
        int r;

        assert(proc_self_mountinfo);

        /* Recursively remount a directory (and all its submounts) read-only or read-write. If the directory is already
         * mounted, we reuse the mount and simply mark it MS_BIND|MS_RDONLY (or remove the MS_RDONLY for read-write
         * operation). If it isn't we first make it one. Afterwards we apply MS_BIND|MS_RDONLY (or remove MS_RDONLY) to
         * all submounts we can access, too. When mounts are stacked on the same mount point we only care for each
         * individual "top-level" mount on each point, as we cannot influence/access the underlying mounts anyway. We
         * do not have any effect on future submounts that might get propagated, they migt be writable. This includes
         * future submounts that have been triggered via autofs.
         *
         * If the "blacklist" parameter is specified it may contain a list of subtrees to exclude from the
         * remount operation. Note that we'll ignore the blacklist for the top-level path. */

        cleaned = strdup(prefix);
        if (!cleaned)
                return -ENOMEM;

        path_simplify(cleaned, false);

        done = set_new(&path_hash_ops);
        if (!done)
                return -ENOMEM;

        for (;;) {
                _cleanup_set_free_free_ Set *todo = NULL;
                bool top_autofs = false;
                char *x;
                unsigned long orig_flags;

                todo = set_new(&path_hash_ops);
                if (!todo)
                        return -ENOMEM;

                rewind(proc_self_mountinfo);

                for (;;) {
                        _cleanup_free_ char *path = NULL, *p = NULL, *type = NULL;
                        int k;

                        k = fscanf(proc_self_mountinfo,
                                   "%*s "       /* (1) mount id */
                                   "%*s "       /* (2) parent id */
                                   "%*s "       /* (3) major:minor */
                                   "%*s "       /* (4) root */
                                   "%ms "       /* (5) mount point */
                                   "%*s"        /* (6) mount options (superblock) */
                                   "%*[^-]"     /* (7) optional fields */
                                   "- "         /* (8) separator */
                                   "%ms "       /* (9) file system type */
                                   "%*s"        /* (10) mount source */
                                   "%*s"        /* (11) mount options (bind mount) */
                                   "%*[^\n]",   /* some rubbish at the end */
                                   &path,
                                   &type);
                        if (k != 2) {
                                if (k == EOF)
                                        break;

                                continue;
                        }

                        r = cunescape(path, UNESCAPE_RELAX, &p);
                        if (r < 0)
                                return r;

                        if (!path_startswith(p, cleaned))
                                continue;

                        /* Ignore this mount if it is blacklisted, but only if it isn't the top-level mount we shall
                         * operate on. */
                        if (!path_equal(cleaned, p)) {
                                bool blacklisted = false;
                                char **i;

                                STRV_FOREACH(i, blacklist) {

                                        if (path_equal(*i, cleaned))
                                                continue;

                                        if (!path_startswith(*i, cleaned))
                                                continue;

                                        if (path_startswith(p, *i)) {
                                                blacklisted = true;
                                                log_debug("Not remounting %s blacklisted by %s, called for %s", p, *i, cleaned);
                                                break;
                                        }
                                }
                                if (blacklisted)
                                        continue;
                        }

                        /* Let's ignore autofs mounts.  If they aren't
                         * triggered yet, we want to avoid triggering
                         * them, as we don't make any guarantees for
                         * future submounts anyway.  If they are
                         * already triggered, then we will find
                         * another entry for this. */
                        if (streq(type, "autofs")) {
                                top_autofs = top_autofs || path_equal(cleaned, p);
                                continue;
                        }

                        if (!set_contains(done, p)) {
                                r = set_consume(todo, p);
                                p = NULL;
                                if (r == -EEXIST)
                                        continue;
                                if (r < 0)
                                        return r;
                        }
                }

                /* If we have no submounts to process anymore and if
                 * the root is either already done, or an autofs, we
                 * are done */
                if (set_isempty(todo) &&
                    (top_autofs || set_contains(done, cleaned)))
                        return 0;

                if (!set_contains(done, cleaned) &&
                    !set_contains(todo, cleaned)) {
                        /* The prefix directory itself is not yet a mount, make it one. */
                        if (mount(cleaned, cleaned, NULL, MS_BIND|MS_REC, NULL) < 0)
                                return -errno;

                        orig_flags = 0;
                        (void) get_mount_flags(cleaned, &orig_flags);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, cleaned, NULL, orig_flags|MS_BIND|MS_REMOUNT|(ro ? MS_RDONLY : 0), NULL) < 0)
                                return -errno;

                        log_debug("Made top-level directory %s a mount point.", prefix);

                        x = strdup(cleaned);
                        if (!x)
                                return -ENOMEM;

                        r = set_consume(done, x);
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
                        if (IN_SET(r, -EACCES, -EPERM)) {
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
                        if (r < 0)
                                return r;

                        /* Try to reuse the original flag set */
                        orig_flags = 0;
                        (void) get_mount_flags(x, &orig_flags);
                        orig_flags &= ~MS_RDONLY;

                        if (mount(NULL, x, NULL, orig_flags|MS_BIND|MS_REMOUNT|(ro ? MS_RDONLY : 0), NULL) < 0)
                                return -errno;

                        log_debug("Remounted %s read-only.", x);
                }
        }
}

int bind_remount_recursive(const char *prefix, bool ro, char **blacklist) {
        _cleanup_fclose_ FILE *proc_self_mountinfo = NULL;

        proc_self_mountinfo = fopen("/proc/self/mountinfo", "re");
        if (!proc_self_mountinfo)
                return -errno;

        (void) __fsetlocking(proc_self_mountinfo, FSETLOCKING_BYCALLER);

        return bind_remount_recursive_with_mountinfo(prefix, ro, blacklist, proc_self_mountinfo);
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

const char* mode_to_inaccessible_node(mode_t mode) {
        /* This function maps a node type to a corresponding inaccessible file node. These nodes are created during
         * early boot by PID 1. In some cases we lacked the privs to create the character and block devices (maybe
         * because we run in an userns environment, or miss CAP_SYS_MKNOD, or run with a devices policy that excludes
         * device nodes with major and minor of 0), but that's fine, in that case we use an AF_UNIX file node instead,
         * which is not the same, but close enough for most uses. And most importantly, the kernel allows bind mounts
         * from socket nodes to any non-directory file nodes, and that's the most important thing that matters. */

        switch(mode & S_IFMT) {
                case S_IFREG:
                        return "/run/systemd/inaccessible/reg";

                case S_IFDIR:
                        return "/run/systemd/inaccessible/dir";

                case S_IFCHR:
                        if (access("/run/systemd/inaccessible/chr", F_OK) == 0)
                                return "/run/systemd/inaccessible/chr";
                        return "/run/systemd/inaccessible/sock";

                case S_IFBLK:
                        if (access("/run/systemd/inaccessible/blk", F_OK) == 0)
                                return "/run/systemd/inaccessible/blk";
                        return "/run/systemd/inaccessible/sock";

                case S_IFIFO:
                        return "/run/systemd/inaccessible/fifo";

                case S_IFSOCK:
                        return "/run/systemd/inaccessible/sock";
        }
        return NULL;
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

int mount_verbose(
                int error_log_level,
                const char *what,
                const char *where,
                const char *type,
                unsigned long flags,
                const char *options) {

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
                log_debug("Mounting %s on %s (%s \"%s\")...",
                          strna(type), where, strnull(fl), strempty(o));
        if (mount(what, where, type, f, o) < 0)
                return log_full_errno(error_log_level, errno,
                                      "Failed to mount %s (type %s) on %s (%s \"%s\"): %m",
                                      strna(what), strna(type), where, strnull(fl), strempty(o));
        return 0;
}

int umount_verbose(const char *what) {
        log_debug("Umounting %s...", what);
        if (umount(what) < 0)
                return log_error_errno(errno, "Failed to unmount %s: %m", what);
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
         * then '*ret_remaining_options' is set to NULL instread of empty string.
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

                r = extract_first_word(&p, &word, ",", EXTRACT_QUOTES);
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
                if (!ent->name && !strextend_with_separator(&ret, ",", word, NULL))
                        return -ENOMEM;
        }

        *ret_mount_flags = mount_flags;
        *ret_remaining_options = TAKE_PTR(ret);

        return 0;
}
