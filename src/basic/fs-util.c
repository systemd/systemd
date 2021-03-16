/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <linux/falloc.h>
#include <linux/magic.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blockdev-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "locale-util.h"
#include "log.h"
#include "macro.h"
#include "missing_fcntl.h"
#include "missing_fs.h"
#include "missing_syscall.h"
#include "mkdir.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "util.h"

int unlink_noerrno(const char *path) {
        PROTECT_ERRNO;
        int r;

        r = unlink(path);
        if (r < 0)
                return -errno;

        return 0;
}

int rmdir_parents(const char *path, const char *stop) {
        size_t l;
        int r = 0;

        assert(path);
        assert(stop);

        l = strlen(path);

        /* Skip trailing slashes */
        while (l > 0 && path[l-1] == '/')
                l--;

        while (l > 0) {
                char *t;

                /* Skip last component */
                while (l > 0 && path[l-1] != '/')
                        l--;

                /* Skip trailing slashes */
                while (l > 0 && path[l-1] == '/')
                        l--;

                if (l <= 0)
                        break;

                t = strndup(path, l);
                if (!t)
                        return -ENOMEM;

                if (path_startswith(stop, t)) {
                        free(t);
                        return 0;
                }

                r = rmdir(t);
                free(t);

                if (r < 0)
                        if (errno != ENOENT)
                                return -errno;
        }

        return 0;
}

int rename_noreplace(int olddirfd, const char *oldpath, int newdirfd, const char *newpath) {
        int r;

        /* Try the ideal approach first */
        if (renameat2(olddirfd, oldpath, newdirfd, newpath, RENAME_NOREPLACE) >= 0)
                return 0;

        /* renameat2() exists since Linux 3.15, btrfs and FAT added support for it later. If it is not implemented,
         * fall back to a different method. */
        if (!ERRNO_IS_NOT_SUPPORTED(errno) && errno != EINVAL)
                return -errno;

        /* Let's try to use linkat()+unlinkat() as fallback. This doesn't work on directories and on some file systems
         * that do not support hard links (such as FAT, most prominently), but for files it's pretty close to what we
         * want — though not atomic (i.e. for a short period both the new and the old filename will exist). */
        if (linkat(olddirfd, oldpath, newdirfd, newpath, 0) >= 0) {

                if (unlinkat(olddirfd, oldpath, 0) < 0) {
                        r = -errno; /* Backup errno before the following unlinkat() alters it */
                        (void) unlinkat(newdirfd, newpath, 0);
                        return r;
                }

                return 0;
        }

        if (!ERRNO_IS_NOT_SUPPORTED(errno) && !IN_SET(errno, EINVAL, EPERM)) /* FAT returns EPERM on link()… */
                return -errno;

        /* OK, neither RENAME_NOREPLACE nor linkat()+unlinkat() worked. Let's then fall back to the racy TOCTOU
         * vulnerable accessat(F_OK) check followed by classic, replacing renameat(), we have nothing better. */

        if (faccessat(newdirfd, newpath, F_OK, AT_SYMLINK_NOFOLLOW) >= 0)
                return -EEXIST;
        if (errno != ENOENT)
                return -errno;

        if (renameat(olddirfd, oldpath, newdirfd, newpath) < 0)
                return -errno;

        return 0;
}

int readlinkat_malloc(int fd, const char *p, char **ret) {
        size_t l = PATH_MAX;

        assert(p);
        assert(ret);

        for (;;) {
                _cleanup_free_ char *c = NULL;
                ssize_t n;

                c = new(char, l+1);
                if (!c)
                        return -ENOMEM;

                n = readlinkat(fd, p, c, l);
                if (n < 0)
                        return -errno;

                if ((size_t) n < l) {
                        c[n] = 0;
                        *ret = TAKE_PTR(c);
                        return 0;
                }

                if (l > (SSIZE_MAX-1)/2) /* readlinkat() returns an ssize_t, and we want an extra byte for a
                                          * trailing NUL, hence do an overflow check relative to SSIZE_MAX-1
                                          * here */
                        return -EFBIG;

                l *= 2;
        }
}

int readlink_malloc(const char *p, char **ret) {
        return readlinkat_malloc(AT_FDCWD, p, ret);
}

int readlink_value(const char *p, char **ret) {
        _cleanup_free_ char *link = NULL;
        char *value;
        int r;

        r = readlink_malloc(p, &link);
        if (r < 0)
                return r;

        value = basename(link);
        if (!value)
                return -ENOENT;

        value = strdup(value);
        if (!value)
                return -ENOMEM;

        *ret = value;

        return 0;
}

int readlink_and_make_absolute(const char *p, char **r) {
        _cleanup_free_ char *target = NULL;
        char *k;
        int j;

        assert(p);
        assert(r);

        j = readlink_malloc(p, &target);
        if (j < 0)
                return j;

        k = file_in_same_dir(p, target);
        if (!k)
                return -ENOMEM;

        *r = k;
        return 0;
}

int chmod_and_chown(const char *path, mode_t mode, uid_t uid, gid_t gid) {
        _cleanup_close_ int fd = -1;

        assert(path);

        fd = open(path, O_PATH|O_CLOEXEC|O_NOFOLLOW); /* Let's acquire an O_PATH fd, as precaution to change
                                                       * mode/owner on the same file */
        if (fd < 0)
                return -errno;

        return fchmod_and_chown(fd, mode, uid, gid);
}

int fchmod_and_chown(int fd, mode_t mode, uid_t uid, gid_t gid) {
        bool do_chown, do_chmod;
        struct stat st;
        int r;

        /* Change ownership and access mode of the specified fd. Tries to do so safely, ensuring that at no
         * point in time the access mode is above the old access mode under the old ownership or the new
         * access mode under the new ownership. Note: this call tries hard to leave the access mode
         * unaffected if the uid/gid is changed, i.e. it undoes implicit suid/sgid dropping the kernel does
         * on chown().
         *
         * This call is happy with O_PATH fds. */

        if (fstat(fd, &st) < 0)
                return -errno;

        do_chown =
                (uid != UID_INVALID && st.st_uid != uid) ||
                (gid != GID_INVALID && st.st_gid != gid);

        do_chmod =
                !S_ISLNK(st.st_mode) && /* chmod is not defined on symlinks */
                ((mode != MODE_INVALID && ((st.st_mode ^ mode) & 07777) != 0) ||
                 do_chown); /* If we change ownership, make sure we reset the mode afterwards, since chown()
                             * modifies the access mode too */

        if (mode == MODE_INVALID)
                mode = st.st_mode; /* If we only shall do a chown(), save original mode, since chown() might break it. */
        else if ((mode & S_IFMT) != 0 && ((mode ^ st.st_mode) & S_IFMT) != 0)
                return -EINVAL; /* insist on the right file type if it was specified */

        if (do_chown && do_chmod) {
                mode_t minimal = st.st_mode & mode; /* the subset of the old and the new mask */

                if (((minimal ^ st.st_mode) & 07777) != 0) {
                        r = fchmod_opath(fd, minimal & 07777);
                        if (r < 0)
                                return r;
                }
        }

        if (do_chown)
                if (fchownat(fd, "", uid, gid, AT_EMPTY_PATH) < 0)
                        return -errno;

        if (do_chmod) {
                r = fchmod_opath(fd, mode & 07777);
                if (r < 0)
                        return r;
        }

        return do_chown || do_chmod;
}

int fchmod_umask(int fd, mode_t m) {
        mode_t u;
        int r;

        u = umask(0777);
        r = fchmod(fd, m & (~u)) < 0 ? -errno : 0;
        umask(u);

        return r;
}

int fchmod_opath(int fd, mode_t m) {
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];

        /* This function operates also on fd that might have been opened with
         * O_PATH. Indeed fchmodat() doesn't have the AT_EMPTY_PATH flag like
         * fchownat() does. */

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        if (chmod(procfs_path, m) < 0) {
                if (errno != ENOENT)
                        return -errno;

                if (proc_mounted() == 0)
                        return -ENOSYS; /* if we have no /proc/, the concept is not implementable */

                return -ENOENT;
        }

        return 0;
}

int futimens_opath(int fd, const struct timespec ts[2]) {
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];

        /* Similar to fchmod_path() but for futimens() */

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        if (utimensat(AT_FDCWD, procfs_path, ts, 0) < 0) {
                if (errno != ENOENT)
                        return -errno;

                if (proc_mounted() == 0)
                        return -ENOSYS; /* if we have no /proc/, the concept is not implementable */

                return -ENOENT;
        }

        return 0;
}

int stat_warn_permissions(const char *path, const struct stat *st) {
        assert(path);
        assert(st);

        /* Don't complain if we are reading something that is not a file, for example /dev/null */
        if (!S_ISREG(st->st_mode))
                return 0;

        if (st->st_mode & 0111)
                log_warning("Configuration file %s is marked executable. Please remove executable permission bits. Proceeding anyway.", path);

        if (st->st_mode & 0002)
                log_warning("Configuration file %s is marked world-writable. Please remove world writability permission bits. Proceeding anyway.", path);

        if (getpid_cached() == 1 && (st->st_mode & 0044) != 0044)
                log_warning("Configuration file %s is marked world-inaccessible. This has no effect as configuration data is accessible via APIs without restrictions. Proceeding anyway.", path);

        return 0;
}

int fd_warn_permissions(const char *path, int fd) {
        struct stat st;

        assert(path);
        assert(fd >= 0);

        if (fstat(fd, &st) < 0)
                return -errno;

        return stat_warn_permissions(path, &st);
}

int touch_file(const char *path, bool parents, usec_t stamp, uid_t uid, gid_t gid, mode_t mode) {
        char fdpath[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_close_ int fd = -1;
        int r, ret = 0;

        assert(path);

        /* Note that touch_file() does not follow symlinks: if invoked on an existing symlink, then it is the symlink
         * itself which is updated, not its target
         *
         * Returns the first error we encounter, but tries to apply as much as possible. */

        if (parents)
                (void) mkdir_parents(path, 0755);

        /* Initially, we try to open the node with O_PATH, so that we get a reference to the node. This is useful in
         * case the path refers to an existing device or socket node, as we can open it successfully in all cases, and
         * won't trigger any driver magic or so. */
        fd = open(path, O_PATH|O_CLOEXEC|O_NOFOLLOW);
        if (fd < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* if the node doesn't exist yet, we create it, but with O_EXCL, so that we only create a regular file
                 * here, and nothing else */
                fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, IN_SET(mode, 0, MODE_INVALID) ? 0644 : mode);
                if (fd < 0)
                        return -errno;
        }

        /* Let's make a path from the fd, and operate on that. With this logic, we can adjust the access mode,
         * ownership and time of the file node in all cases, even if the fd refers to an O_PATH object — which is
         * something fchown(), fchmod(), futimensat() don't allow. */
        xsprintf(fdpath, "/proc/self/fd/%i", fd);

        ret = fchmod_and_chown(fd, mode, uid, gid);

        if (stamp != USEC_INFINITY) {
                struct timespec ts[2];

                timespec_store(&ts[0], stamp);
                ts[1] = ts[0];
                r = utimensat(AT_FDCWD, fdpath, ts, 0);
        } else
                r = utimensat(AT_FDCWD, fdpath, NULL, 0);
        if (r < 0 && ret >= 0)
                return -errno;

        return ret;
}

int touch(const char *path) {
        return touch_file(path, false, USEC_INFINITY, UID_INVALID, GID_INVALID, MODE_INVALID);
}

int symlink_idempotent(const char *from, const char *to, bool make_relative) {
        _cleanup_free_ char *relpath = NULL;
        int r;

        assert(from);
        assert(to);

        if (make_relative) {
                _cleanup_free_ char *parent = NULL;

                r = path_extract_directory(to, &parent);
                if (r < 0)
                        return r;

                r = path_make_relative(parent, from, &relpath);
                if (r < 0)
                        return r;

                from = relpath;
        }

        if (symlink(from, to) < 0) {
                _cleanup_free_ char *p = NULL;

                if (errno != EEXIST)
                        return -errno;

                r = readlink_malloc(to, &p);
                if (r == -EINVAL) /* Not a symlink? In that case return the original error we encountered: -EEXIST */
                        return -EEXIST;
                if (r < 0) /* Any other error? In that case propagate it as is */
                        return r;

                if (!streq(p, from)) /* Not the symlink we want it to be? In that case, propagate the original -EEXIST */
                        return -EEXIST;
        }

        return 0;
}

int symlink_atomic(const char *from, const char *to) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(from);
        assert(to);

        r = tempfn_random(to, NULL, &t);
        if (r < 0)
                return r;

        if (symlink(from, t) < 0)
                return -errno;

        if (rename(t, to) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int mknod_atomic(const char *path, mode_t mode, dev_t dev) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(path);

        r = tempfn_random(path, NULL, &t);
        if (r < 0)
                return r;

        if (mknod(t, mode, dev) < 0)
                return -errno;

        if (rename(t, path) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int mkfifo_atomic(const char *path, mode_t mode) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(path);

        r = tempfn_random(path, NULL, &t);
        if (r < 0)
                return r;

        if (mkfifo(t, mode) < 0)
                return -errno;

        if (rename(t, path) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int mkfifoat_atomic(int dirfd, const char *path, mode_t mode) {
        _cleanup_free_ char *t = NULL;
        int r;

        assert(path);

        if (path_is_absolute(path))
                return mkfifo_atomic(path, mode);

        /* We're only interested in the (random) filename.  */
        r = tempfn_random_child("", NULL, &t);
        if (r < 0)
                return r;

        if (mkfifoat(dirfd, t, mode) < 0)
                return -errno;

        if (renameat(dirfd, t, dirfd, path) < 0) {
                unlink_noerrno(t);
                return -errno;
        }

        return 0;
}

int get_files_in_directory(const char *path, char ***list) {
        _cleanup_closedir_ DIR *d = NULL;
        struct dirent *de;
        size_t bufsize = 0, n = 0;
        _cleanup_strv_free_ char **l = NULL;

        assert(path);

        /* Returns all files in a directory in *list, and the number
         * of files as return value. If list is NULL returns only the
         * number. */

        d = opendir(path);
        if (!d)
                return -errno;

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                dirent_ensure_type(d, de);

                if (!dirent_is_file(de))
                        continue;

                if (list) {
                        /* one extra slot is needed for the terminating NULL */
                        if (!GREEDY_REALLOC(l, bufsize, n + 2))
                                return -ENOMEM;

                        l[n] = strdup(de->d_name);
                        if (!l[n])
                                return -ENOMEM;

                        l[++n] = NULL;
                } else
                        n++;
        }

        if (list)
                *list = TAKE_PTR(l);

        return n;
}

static int getenv_tmp_dir(const char **ret_path) {
        const char *n;
        int r, ret = 0;

        assert(ret_path);

        /* We use the same order of environment variables python uses in tempfile.gettempdir():
         * https://docs.python.org/3/library/tempfile.html#tempfile.gettempdir */
        FOREACH_STRING(n, "TMPDIR", "TEMP", "TMP") {
                const char *e;

                e = secure_getenv(n);
                if (!e)
                        continue;
                if (!path_is_absolute(e)) {
                        r = -ENOTDIR;
                        goto next;
                }
                if (!path_is_normalized(e)) {
                        r = -EPERM;
                        goto next;
                }

                r = is_dir(e, true);
                if (r < 0)
                        goto next;
                if (r == 0) {
                        r = -ENOTDIR;
                        goto next;
                }

                *ret_path = e;
                return 1;

        next:
                /* Remember first error, to make this more debuggable */
                if (ret >= 0)
                        ret = r;
        }

        if (ret < 0)
                return ret;

        *ret_path = NULL;
        return ret;
}

static int tmp_dir_internal(const char *def, const char **ret) {
        const char *e;
        int r, k;

        assert(def);
        assert(ret);

        r = getenv_tmp_dir(&e);
        if (r > 0) {
                *ret = e;
                return 0;
        }

        k = is_dir(def, true);
        if (k == 0)
                k = -ENOTDIR;
        if (k < 0)
                return r < 0 ? r : k;

        *ret = def;
        return 0;
}

int var_tmp_dir(const char **ret) {

        /* Returns the location for "larger" temporary files, that is backed by physical storage if available, and thus
         * even might survive a boot: /var/tmp. If $TMPDIR (or related environment variables) are set, its value is
         * returned preferably however. Note that both this function and tmp_dir() below are affected by $TMPDIR,
         * making it a variable that overrides all temporary file storage locations. */

        return tmp_dir_internal("/var/tmp", ret);
}

int tmp_dir(const char **ret) {

        /* Similar to var_tmp_dir() above, but returns the location for "smaller" temporary files, which is usually
         * backed by an in-memory file system: /tmp. */

        return tmp_dir_internal("/tmp", ret);
}

int unlink_or_warn(const char *filename) {
        if (unlink(filename) < 0 && errno != ENOENT)
                /* If the file doesn't exist and the fs simply was read-only (in which
                 * case unlink() returns EROFS even if the file doesn't exist), don't
                 * complain */
                if (errno != EROFS || access(filename, F_OK) >= 0)
                        return log_error_errno(errno, "Failed to remove \"%s\": %m", filename);

        return 0;
}

int inotify_add_watch_fd(int fd, int what, uint32_t mask) {
        char path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int) + 1];
        int wd;

        /* This is like inotify_add_watch(), except that the file to watch is not referenced by a path, but by an fd */
        xsprintf(path, "/proc/self/fd/%i", what);

        wd = inotify_add_watch(fd, path, mask);
        if (wd < 0)
                return -errno;

        return wd;
}

int inotify_add_watch_and_warn(int fd, const char *pathname, uint32_t mask) {
        int wd;

        wd = inotify_add_watch(fd, pathname, mask);
        if (wd < 0) {
                if (errno == ENOSPC)
                        return log_error_errno(errno, "Failed to add a watch for %s: inotify watch limit reached", pathname);

                return log_error_errno(errno, "Failed to add a watch for %s: %m", pathname);
        }

        return wd;
}

static bool unsafe_transition(const struct stat *a, const struct stat *b) {
        /* Returns true if the transition from a to b is safe, i.e. that we never transition from unprivileged to
         * privileged files or directories. Why bother? So that unprivileged code can't symlink to privileged files
         * making us believe we read something safe even though it isn't safe in the specific context we open it in. */

        if (a->st_uid == 0) /* Transitioning from privileged to unprivileged is always fine */
                return false;

        return a->st_uid != b->st_uid; /* Otherwise we need to stay within the same UID */
}

static int log_unsafe_transition(int a, int b, const char *path, unsigned flags) {
        _cleanup_free_ char *n1 = NULL, *n2 = NULL;

        if (!FLAGS_SET(flags, CHASE_WARN))
                return -ENOLINK;

        (void) fd_get_path(a, &n1);
        (void) fd_get_path(b, &n2);

        return log_warning_errno(SYNTHETIC_ERRNO(ENOLINK),
                                 "Detected unsafe path transition %s %s %s during canonicalization of %s.",
                                 strna(n1), special_glyph(SPECIAL_GLYPH_ARROW), strna(n2), path);
}

static int log_autofs_mount_point(int fd, const char *path, unsigned flags) {
        _cleanup_free_ char *n1 = NULL;

        if (!FLAGS_SET(flags, CHASE_WARN))
                return -EREMOTE;

        (void) fd_get_path(fd, &n1);

        return log_warning_errno(SYNTHETIC_ERRNO(EREMOTE),
                                 "Detected autofs mount point %s during canonicalization of %s.",
                                 strna(n1), path);
}

int chase_symlinks(const char *path, const char *original_root, unsigned flags, char **ret_path, int *ret_fd) {
        _cleanup_free_ char *buffer = NULL, *done = NULL, *root = NULL;
        _cleanup_close_ int fd = -1;
        unsigned max_follow = CHASE_SYMLINKS_MAX; /* how many symlinks to follow before giving up and returning ELOOP */
        struct stat previous_stat;
        bool exists = true;
        char *todo;
        int r;

        assert(path);

        /* Either the file may be missing, or we return an fd to the final object, but both make no sense */
        if ((flags & CHASE_NONEXISTENT) && ret_fd)
                return -EINVAL;

        if ((flags & CHASE_STEP) && ret_fd)
                return -EINVAL;

        if (isempty(path))
                return -EINVAL;

        /* This is a lot like canonicalize_file_name(), but takes an additional "root" parameter, that allows following
         * symlinks relative to a root directory, instead of the root of the host.
         *
         * Note that "root" primarily matters if we encounter an absolute symlink. It is also used when following
         * relative symlinks to ensure they cannot be used to "escape" the root directory. The path parameter passed is
         * assumed to be already prefixed by it, except if the CHASE_PREFIX_ROOT flag is set, in which case it is first
         * prefixed accordingly.
         *
         * Algorithmically this operates on two path buffers: "done" are the components of the path we already
         * processed and resolved symlinks, "." and ".." of. "todo" are the components of the path we still need to
         * process. On each iteration, we move one component from "todo" to "done", processing it's special meaning
         * each time. The "todo" path always starts with at least one slash, the "done" path always ends in no
         * slash. We always keep an O_PATH fd to the component we are currently processing, thus keeping lookup races
         * to a minimum.
         *
         * Suggested usage: whenever you want to canonicalize a path, use this function. Pass the absolute path you got
         * as-is: fully qualified and relative to your host's root. Optionally, specify the root parameter to tell this
         * function what to do when encountering a symlink with an absolute path as directory: prefix it by the
         * specified path.
         *
         * There are five ways to invoke this function:
         *
         * 1. Without CHASE_STEP or ret_fd: in this case the path is resolved and the normalized path is
         *    returned in `ret_path`. The return value is < 0 on error. If CHASE_NONEXISTENT is also set, 0
         *    is returned if the file doesn't exist, > 0 otherwise. If CHASE_NONEXISTENT is not set, >= 0 is
         *    returned if the destination was found, -ENOENT if it wasn't.
         *
         * 2. With ret_fd: in this case the destination is opened after chasing it as O_PATH and this file
         *    descriptor is returned as return value. This is useful to open files relative to some root
         *    directory. Note that the returned O_PATH file descriptors must be converted into a regular one (using
         *    fd_reopen() or such) before it can be used for reading/writing. ret_fd may not be combined with
         *    CHASE_NONEXISTENT.
         *
         * 3. With CHASE_STEP: in this case only a single step of the normalization is executed, i.e. only the first
         *    symlink or ".." component of the path is resolved, and the resulting path is returned. This is useful if
         *    a caller wants to trace the path through the file system verbosely. Returns < 0 on error, > 0 if the
         *    path is fully normalized, and == 0 for each normalization step. This may be combined with
         *    CHASE_NONEXISTENT, in which case 1 is returned when a component is not found.
         *
         * 4. With CHASE_SAFE: in this case the path must not contain unsafe transitions, i.e. transitions from
         *    unprivileged to privileged files or directories. In such cases the return value is -ENOLINK. If
         *    CHASE_WARN is also set, a warning describing the unsafe transition is emitted.
         *
         * 5. With CHASE_NO_AUTOFS: in this case if an autofs mount point is encountered, path normalization
         *    is aborted and -EREMOTE is returned. If CHASE_WARN is also set, a warning showing the path of
         *    the mount point is emitted.
         */

        /* A root directory of "/" or "" is identical to none */
        if (empty_or_root(original_root))
                original_root = NULL;

        if (!original_root && !ret_path && !(flags & (CHASE_NONEXISTENT|CHASE_NO_AUTOFS|CHASE_SAFE|CHASE_STEP)) && ret_fd) {
                /* Shortcut the ret_fd case if the caller isn't interested in the actual path and has no root set
                 * and doesn't care about any of the other special features we provide either. */
                r = open(path, O_PATH|O_CLOEXEC|((flags & CHASE_NOFOLLOW) ? O_NOFOLLOW : 0));
                if (r < 0)
                        return -errno;

                *ret_fd = r;
                return 0;
        }

        if (original_root) {
                r = path_make_absolute_cwd(original_root, &root);
                if (r < 0)
                        return r;

                /* Simplify the root directory, so that it has no duplicate slashes and nothing at the
                 * end. While we won't resolve the root path we still simplify it. Note that dropping the
                 * trailing slash should not change behaviour, since when opening it we specify O_DIRECTORY
                 * anyway. Moreover at the end of this function after processing everything we'll always turn
                 * the empty string back to "/". */
                delete_trailing_chars(root, "/");
                path_simplify(root, true);

                if (flags & CHASE_PREFIX_ROOT) {
                        /* We don't support relative paths in combination with a root directory */
                        if (!path_is_absolute(path))
                                return -EINVAL;

                        path = prefix_roota(root, path);
                }
        }

        r = path_make_absolute_cwd(path, &buffer);
        if (r < 0)
                return r;

        fd = open(root ?: "/", O_CLOEXEC|O_DIRECTORY|O_PATH);
        if (fd < 0)
                return -errno;

        if (flags & CHASE_SAFE) {
                if (fstat(fd, &previous_stat) < 0)
                        return -errno;
        }

        if (root) {
                _cleanup_free_ char *absolute = NULL;
                const char *e;

                /* If we are operating on a root directory, let's take the root directory as it is. */

                e = path_startswith(buffer, root);
                if (!e)
                        return log_full_errno(flags & CHASE_WARN ? LOG_WARNING : LOG_DEBUG,
                                              SYNTHETIC_ERRNO(ECHRNG),
                                              "Specified path '%s' is outside of specified root directory '%s', refusing to resolve.",
                                              path, root);

                done = strdup(root);
                if (!done)
                        return -ENOMEM;

                /* Make sure "todo" starts with a slash */
                absolute = strjoin("/", e);
                if (!absolute)
                        return -ENOMEM;

                free_and_replace(buffer, absolute);
        }

        todo = buffer;
        for (;;) {
                _cleanup_free_ char *first = NULL;
                _cleanup_close_ int child = -1;
                struct stat st;
                size_t n, m;

                /* Determine length of first component in the path */
                n = strspn(todo, "/");                  /* The slashes */

                if (n > 1) {
                        /* If we are looking at more than a single slash then skip all but one, so that when
                         * we are done with everything we have a normalized path with only single slashes
                         * separating the path components. */
                        todo += n - 1;
                        n = 1;
                }

                m = n + strcspn(todo + n, "/");         /* The entire length of the component */

                /* Extract the first component. */
                first = strndup(todo, m);
                if (!first)
                        return -ENOMEM;

                todo += m;

                /* Empty? Then we reached the end. */
                if (isempty(first))
                        break;

                /* Just a single slash? Then we reached the end. */
                if (path_equal(first, "/")) {
                        /* Preserve the trailing slash */

                        if (flags & CHASE_TRAIL_SLASH)
                                if (!strextend(&done, "/"))
                                        return -ENOMEM;

                        break;
                }

                /* Just a dot? Then let's eat this up. */
                if (path_equal(first, "/."))
                        continue;

                /* Two dots? Then chop off the last bit of what we already found out. */
                if (path_equal(first, "/..")) {
                        _cleanup_free_ char *parent = NULL;
                        _cleanup_close_ int fd_parent = -1;

                        /* If we already are at the top, then going up will not change anything. This is in-line with
                         * how the kernel handles this. */
                        if (empty_or_root(done))
                                continue;

                        parent = dirname_malloc(done);
                        if (!parent)
                                return -ENOMEM;

                        /* Don't allow this to leave the root dir.  */
                        if (root &&
                            path_startswith(done, root) &&
                            !path_startswith(parent, root))
                                continue;

                        free_and_replace(done, parent);

                        if (flags & CHASE_STEP)
                                goto chased_one;

                        fd_parent = openat(fd, "..", O_CLOEXEC|O_NOFOLLOW|O_PATH);
                        if (fd_parent < 0)
                                return -errno;

                        if (flags & CHASE_SAFE) {
                                if (fstat(fd_parent, &st) < 0)
                                        return -errno;

                                if (unsafe_transition(&previous_stat, &st))
                                        return log_unsafe_transition(fd, fd_parent, path, flags);

                                previous_stat = st;
                        }

                        safe_close(fd);
                        fd = TAKE_FD(fd_parent);

                        continue;
                }

                /* Otherwise let's see what this is. */
                child = openat(fd, first + n, O_CLOEXEC|O_NOFOLLOW|O_PATH);
                if (child < 0) {

                        if (errno == ENOENT &&
                            (flags & CHASE_NONEXISTENT) &&
                            (isempty(todo) || path_is_normalized(todo))) {

                                /* If CHASE_NONEXISTENT is set, and the path does not exist, then that's OK, return
                                 * what we got so far. But don't allow this if the remaining path contains "../ or "./"
                                 * or something else weird. */

                                /* If done is "/", as first also contains slash at the head, then remove this redundant slash. */
                                if (streq_ptr(done, "/"))
                                        *done = '\0';

                                if (!strextend(&done, first, todo))
                                        return -ENOMEM;

                                exists = false;
                                break;
                        }

                        return -errno;
                }

                if (fstat(child, &st) < 0)
                        return -errno;
                if ((flags & CHASE_SAFE) &&
                    unsafe_transition(&previous_stat, &st))
                        return log_unsafe_transition(fd, child, path, flags);

                previous_stat = st;

                if ((flags & CHASE_NO_AUTOFS) &&
                    fd_is_fs_type(child, AUTOFS_SUPER_MAGIC) > 0)
                        return log_autofs_mount_point(child, path, flags);

                if (S_ISLNK(st.st_mode) && !((flags & CHASE_NOFOLLOW) && isempty(todo))) {
                        char *joined;
                        _cleanup_free_ char *destination = NULL;

                        /* This is a symlink, in this case read the destination. But let's make sure we don't follow
                         * symlinks without bounds. */
                        if (--max_follow <= 0)
                                return -ELOOP;

                        r = readlinkat_malloc(fd, first + n, &destination);
                        if (r < 0)
                                return r;
                        if (isempty(destination))
                                return -EINVAL;

                        if (path_is_absolute(destination)) {

                                /* An absolute destination. Start the loop from the beginning, but use the root
                                 * directory as base. */

                                safe_close(fd);
                                fd = open(root ?: "/", O_CLOEXEC|O_DIRECTORY|O_PATH);
                                if (fd < 0)
                                        return -errno;

                                if (flags & CHASE_SAFE) {
                                        if (fstat(fd, &st) < 0)
                                                return -errno;

                                        if (unsafe_transition(&previous_stat, &st))
                                                return log_unsafe_transition(child, fd, path, flags);

                                        previous_stat = st;
                                }

                                free(done);

                                /* Note that we do not revalidate the root, we take it as is. */
                                if (isempty(root))
                                        done = NULL;
                                else {
                                        done = strdup(root);
                                        if (!done)
                                                return -ENOMEM;
                                }

                                /* Prefix what's left to do with what we just read, and start the loop again, but
                                 * remain in the current directory. */
                                joined = path_join(destination, todo);
                        } else
                                joined = path_join("/", destination, todo);
                        if (!joined)
                                return -ENOMEM;

                        free(buffer);
                        todo = buffer = joined;

                        if (flags & CHASE_STEP)
                                goto chased_one;

                        continue;
                }

                /* If this is not a symlink, then let's just add the name we read to what we already verified. */
                if (!done)
                        done = TAKE_PTR(first);
                else {
                        /* If done is "/", as first also contains slash at the head, then remove this redundant slash. */
                        if (streq(done, "/"))
                                *done = '\0';

                        if (!strextend(&done, first))
                                return -ENOMEM;
                }

                /* And iterate again, but go one directory further down. */
                safe_close(fd);
                fd = TAKE_FD(child);
        }

        if (!done) {
                /* Special case, turn the empty string into "/", to indicate the root directory. */
                done = strdup("/");
                if (!done)
                        return -ENOMEM;
        }

        if (ret_path)
                *ret_path = TAKE_PTR(done);

        if (ret_fd) {
                /* Return the O_PATH fd we currently are looking to the caller. It can translate it to a
                 * proper fd by opening /proc/self/fd/xyz. */

                assert(fd >= 0);
                *ret_fd = TAKE_FD(fd);
        }

        if (flags & CHASE_STEP)
                return 1;

        return exists;

chased_one:
        if (ret_path) {
                char *c;

                c = strjoin(strempty(done), todo);
                if (!c)
                        return -ENOMEM;

                *ret_path = c;
        }

        return 0;
}

int chase_symlinks_and_open(
                const char *path,
                const char *root,
                unsigned chase_flags,
                int open_flags,
                char **ret_path) {

        _cleanup_close_ int path_fd = -1;
        _cleanup_free_ char *p = NULL;
        int r;

        if (chase_flags & CHASE_NONEXISTENT)
                return -EINVAL;

        if (empty_or_root(root) && !ret_path && (chase_flags & (CHASE_NO_AUTOFS|CHASE_SAFE)) == 0) {
                /* Shortcut this call if none of the special features of this call are requested */
                r = open(path, open_flags);
                if (r < 0)
                        return -errno;

                return r;
        }

        r = chase_symlinks(path, root, chase_flags, ret_path ? &p : NULL, &path_fd);
        if (r < 0)
                return r;
        assert(path_fd >= 0);

        r = fd_reopen(path_fd, open_flags);
        if (r < 0)
                return r;

        if (ret_path)
                *ret_path = TAKE_PTR(p);

        return r;
}

int chase_symlinks_and_opendir(
                const char *path,
                const char *root,
                unsigned chase_flags,
                char **ret_path,
                DIR **ret_dir) {

        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        _cleanup_close_ int path_fd = -1;
        _cleanup_free_ char *p = NULL;
        DIR *d;
        int r;

        if (!ret_dir)
                return -EINVAL;
        if (chase_flags & CHASE_NONEXISTENT)
                return -EINVAL;

        if (empty_or_root(root) && !ret_path && (chase_flags & (CHASE_NO_AUTOFS|CHASE_SAFE)) == 0) {
                /* Shortcut this call if none of the special features of this call are requested */
                d = opendir(path);
                if (!d)
                        return -errno;

                *ret_dir = d;
                return 0;
        }

        r = chase_symlinks(path, root, chase_flags, ret_path ? &p : NULL, &path_fd);
        if (r < 0)
                return r;
        assert(path_fd >= 0);

        xsprintf(procfs_path, "/proc/self/fd/%i", path_fd);
        d = opendir(procfs_path);
        if (!d)
                return -errno;

        if (ret_path)
                *ret_path = TAKE_PTR(p);

        *ret_dir = d;
        return 0;
}

int chase_symlinks_and_stat(
                const char *path,
                const char *root,
                unsigned chase_flags,
                char **ret_path,
                struct stat *ret_stat,
                int *ret_fd) {

        _cleanup_close_ int path_fd = -1;
        _cleanup_free_ char *p = NULL;
        int r;

        assert(path);
        assert(ret_stat);

        if (chase_flags & CHASE_NONEXISTENT)
                return -EINVAL;

        if (empty_or_root(root) && !ret_path && (chase_flags & (CHASE_NO_AUTOFS|CHASE_SAFE)) == 0) {
                /* Shortcut this call if none of the special features of this call are requested */
                if (stat(path, ret_stat) < 0)
                        return -errno;

                return 1;
        }

        r = chase_symlinks(path, root, chase_flags, ret_path ? &p : NULL, &path_fd);
        if (r < 0)
                return r;
        assert(path_fd >= 0);

        if (fstat(path_fd, ret_stat) < 0)
                return -errno;

        if (ret_path)
                *ret_path = TAKE_PTR(p);
        if (ret_fd)
                *ret_fd = TAKE_FD(path_fd);

        return 1;
}

int access_fd(int fd, int mode) {
        char p[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(fd) + 1];

        /* Like access() but operates on an already open fd */

        xsprintf(p, "/proc/self/fd/%i", fd);
        if (access(p, mode) < 0) {
                if (errno != ENOENT)
                        return -errno;

                /* ENOENT can mean two things: that the fd does not exist or that /proc is not mounted. Let's
                 * make things debuggable and distinguish the two. */

                if (proc_mounted() == 0)
                        return -ENOSYS;  /* /proc is not available or not set up properly, we're most likely in some chroot
                                          * environment. */

                return -EBADF; /* The directory exists, hence it's the fd that doesn't. */
        }

        return 0;
}

void unlink_tempfilep(char (*p)[]) {
        /* If the file is created with mkstemp(), it will (almost always)
         * change the suffix. Treat this as a sign that the file was
         * successfully created. We ignore both the rare case where the
         * original suffix is used and unlink failures. */
        if (!endswith(*p, ".XXXXXX"))
                (void) unlink_noerrno(*p);
}

int unlinkat_deallocate(int fd, const char *name, UnlinkDeallocateFlags flags) {
        _cleanup_close_ int truncate_fd = -1;
        struct stat st;
        off_t l, bs;

        assert((flags & ~(UNLINK_REMOVEDIR|UNLINK_ERASE)) == 0);

        /* Operates like unlinkat() but also deallocates the file contents if it is a regular file and there's no other
         * link to it. This is useful to ensure that other processes that might have the file open for reading won't be
         * able to keep the data pinned on disk forever. This call is particular useful whenever we execute clean-up
         * jobs ("vacuuming"), where we want to make sure the data is really gone and the disk space released and
         * returned to the free pool.
         *
         * Deallocation is preferably done by FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE (👊) if supported, which means
         * the file won't change size. That's a good thing since we shouldn't needlessly trigger SIGBUS in other
         * programs that have mmap()ed the file. (The assumption here is that changing file contents to all zeroes
         * underneath those programs is the better choice than simply triggering SIGBUS in them which truncation does.)
         * However if hole punching is not implemented in the kernel or file system we'll fall back to normal file
         * truncation (🔪), as our goal of deallocating the data space trumps our goal of being nice to readers (💐).
         *
         * Note that we attempt deallocation, but failure to succeed with that is not considered fatal, as long as the
         * primary job – to delete the file – is accomplished. */

        if (!FLAGS_SET(flags, UNLINK_REMOVEDIR)) {
                truncate_fd = openat(fd, name, O_WRONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW|O_NONBLOCK);
                if (truncate_fd < 0) {

                        /* If this failed because the file doesn't exist propagate the error right-away. Also,
                         * AT_REMOVEDIR wasn't set, and we tried to open the file for writing, which means EISDIR is
                         * returned when this is a directory but we are not supposed to delete those, hence propagate
                         * the error right-away too. */
                        if (IN_SET(errno, ENOENT, EISDIR))
                                return -errno;

                        if (errno != ELOOP) /* don't complain if this is a symlink */
                                log_debug_errno(errno, "Failed to open file '%s' for deallocation, ignoring: %m", name);
                }
        }

        if (unlinkat(fd, name, FLAGS_SET(flags, UNLINK_REMOVEDIR) ? AT_REMOVEDIR : 0) < 0)
                return -errno;

        if (truncate_fd < 0) /* Don't have a file handle, can't do more ☹️ */
                return 0;

        if (fstat(truncate_fd, &st) < 0) {
                log_debug_errno(errno, "Failed to stat file '%s' for deallocation, ignoring: %m", name);
                return 0;
        }

        if (!S_ISREG(st.st_mode))
                return 0;

        if (FLAGS_SET(flags, UNLINK_ERASE) && st.st_size > 0 && st.st_nlink == 0) {
                uint64_t left = st.st_size;
                char buffer[64 * 1024];

                /* If erasing is requested, let's overwrite the file with random data once before deleting
                 * it. This isn't going to give you shred(1) semantics, but hopefully should be good enough
                 * for stuff backed by tmpfs at least.
                 *
                 * Note that we only erase like this if the link count of the file is zero. If it is higher it
                 * is still linked by someone else and we'll leave it to them to remove it securely
                 * eventually! */

                random_bytes(buffer, sizeof(buffer));

                while (left > 0) {
                        ssize_t n;

                        n = write(truncate_fd, buffer, MIN(sizeof(buffer), left));
                        if (n < 0) {
                                log_debug_errno(errno, "Failed to erase data in file '%s', ignoring.", name);
                                break;
                        }

                        assert(left >= (size_t) n);
                        left -= n;
                }

                /* Let's refresh metadata */
                if (fstat(truncate_fd, &st) < 0) {
                        log_debug_errno(errno, "Failed to stat file '%s' for deallocation, ignoring: %m", name);
                        return 0;
                }
        }

        /* Don't dallocate if there's nothing to deallocate or if the file is linked elsewhere */
        if (st.st_blocks == 0 || st.st_nlink > 0)
                return 0;

        /* If this is a regular file, it actually took up space on disk and there are no other links it's time to
         * punch-hole/truncate this to release the disk space. */

        bs = MAX(st.st_blksize, 512);
        l = DIV_ROUND_UP(st.st_size, bs) * bs; /* Round up to next block size */

        if (fallocate(truncate_fd, FALLOC_FL_PUNCH_HOLE|FALLOC_FL_KEEP_SIZE, 0, l) >= 0)
                return 0; /* Successfully punched a hole! 😊 */

        /* Fall back to truncation */
        if (ftruncate(truncate_fd, 0) < 0) {
                log_debug_errno(errno, "Failed to truncate file to 0, ignoring: %m");
                return 0;
        }

        return 0;
}

int fsync_directory_of_file(int fd) {
        _cleanup_free_ char *path = NULL;
        _cleanup_close_ int dfd = -1;
        struct stat st;
        int r;

        assert(fd >= 0);

        /* We only reasonably can do this for regular files and directories, hence check for that */
        if (fstat(fd, &st) < 0)
                return -errno;

        if (S_ISREG(st.st_mode)) {

                r = fd_get_path(fd, &path);
                if (r < 0) {
                        log_debug_errno(r, "Failed to query /proc/self/fd/%d%s: %m",
                                        fd,
                                        r == -ENOSYS ? ", ignoring" : "");

                        if (r == -ENOSYS)
                                /* If /proc is not available, we're most likely running in some
                                 * chroot environment, and syncing the directory is not very
                                 * important in that case. Let's just silently do nothing. */
                                return 0;

                        return r;
                }

                if (!path_is_absolute(path))
                        return -EINVAL;

                dfd = open_parent(path, O_CLOEXEC|O_NOFOLLOW, 0);
                if (dfd < 0)
                        return dfd;

        } else if (S_ISDIR(st.st_mode)) {
                dfd = openat(fd, "..", O_RDONLY|O_DIRECTORY|O_CLOEXEC, 0);
                if (dfd < 0)
                        return -errno;
        } else
                return -ENOTTY;

        if (fsync(dfd) < 0)
                return -errno;

        return 0;
}

int fsync_full(int fd) {
        int r, q;

        /* Sync both the file and the directory */

        r = fsync(fd) < 0 ? -errno : 0;

        q = fsync_directory_of_file(fd);
        if (r < 0) /* Return earlier error */
                return r;
        if (q == -ENOTTY) /* Ignore if the 'fd' refers to a block device or so which doesn't really have a
                           * parent dir */
                return 0;
        return q;
}

int fsync_path_at(int at_fd, const char *path) {
        _cleanup_close_ int opened_fd = -1;
        int fd;

        if (isempty(path)) {
                if (at_fd == AT_FDCWD) {
                        opened_fd = open(".", O_RDONLY|O_DIRECTORY|O_CLOEXEC);
                        if (opened_fd < 0)
                                return -errno;

                        fd = opened_fd;
                } else
                        fd = at_fd;
        } else {
                opened_fd = openat(at_fd, path, O_RDONLY|O_CLOEXEC|O_NONBLOCK);
                if (opened_fd < 0)
                        return -errno;

                fd = opened_fd;
        }

        if (fsync(fd) < 0)
                return -errno;

        return 0;
}

int syncfs_path(int atfd, const char *path) {
        _cleanup_close_ int fd = -1;

        assert(path);

        fd = openat(atfd, path, O_CLOEXEC|O_RDONLY|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        if (syncfs(fd) < 0)
                return -errno;

        return 0;
}

int open_parent(const char *path, int flags, mode_t mode) {
        _cleanup_free_ char *parent = NULL;
        int fd, r;

        r = path_extract_directory(path, &parent);
        if (r < 0)
                return r;

        /* Let's insist on O_DIRECTORY since the parent of a file or directory is a directory. Except if we open an
         * O_TMPFILE file, because in that case we are actually create a regular file below the parent directory. */

        if (FLAGS_SET(flags, O_PATH))
                flags |= O_DIRECTORY;
        else if (!FLAGS_SET(flags, O_TMPFILE))
                flags |= O_DIRECTORY|O_RDONLY;

        fd = open(parent, flags, mode);
        if (fd < 0)
                return -errno;

        return fd;
}

static int blockdev_is_encrypted(const char *sysfs_path, unsigned depth_left) {
        _cleanup_free_ char *p = NULL, *uuids = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        int r, found_encrypted = false;

        assert(sysfs_path);

        if (depth_left == 0)
                return -EINVAL;

        p = path_join(sysfs_path, "dm/uuid");
        if (!p)
                return -ENOMEM;

        r = read_one_line_file(p, &uuids);
        if (r != -ENOENT) {
                if (r < 0)
                        return r;

                /* The DM device's uuid attribute is prefixed with "CRYPT-" if this is a dm-crypt device. */
                if (startswith(uuids, "CRYPT-"))
                        return true;
        }

        /* Not a dm-crypt device itself. But maybe it is on top of one? Follow the links in the "slaves/"
         * subdir. */

        p = mfree(p);
        p = path_join(sysfs_path, "slaves");
        if (!p)
                return -ENOMEM;

        d = opendir(p);
        if (!d) {
                if (errno == ENOENT) /* Doesn't have underlying devices */
                        return false;

                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *q = NULL;
                struct dirent *de;

                errno = 0;
                de = readdir_no_dot(d);
                if (!de) {
                        if (errno != 0)
                                return -errno;

                        break; /* No more underlying devices */
                }

                q = path_join(p, de->d_name);
                if (!q)
                        return -ENOMEM;

                r = blockdev_is_encrypted(q, depth_left - 1);
                if (r < 0)
                        return r;
                if (r == 0) /* we found one that is not encrypted? then propagate that immediately */
                        return false;

                found_encrypted = true;
        }

        return found_encrypted;
}

int path_is_encrypted(const char *path) {
        char p[SYS_BLOCK_PATH_MAX(NULL)];
        dev_t devt;
        int r;

        r = get_block_device(path, &devt);
        if (r < 0)
                return r;
        if (r == 0) /* doesn't have a block device */
                return false;

        xsprintf_sys_block_path(p, NULL, devt);

        return blockdev_is_encrypted(p, 10 /* safety net: maximum recursion depth */);
}

int conservative_renameat(
                int olddirfd, const char *oldpath,
                int newdirfd, const char *newpath) {

        _cleanup_close_ int old_fd = -1, new_fd = -1;
        struct stat old_stat, new_stat;

        /* Renames the old path to thew new path, much like renameat() — except if both are regular files and
         * have the exact same contents and basic file attributes already. In that case remove the new file
         * instead. This call is useful for reducing inotify wakeups on files that are updated but don't
         * actually change. This function is written in a style that we rather rename too often than suppress
         * too much. i.e. whenever we are in doubt we rather rename than fail. After all reducing inotify
         * events is an optimization only, not more. */

        old_fd = openat(olddirfd, oldpath, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW);
        if (old_fd < 0)
                goto do_rename;

        new_fd = openat(newdirfd, newpath, O_CLOEXEC|O_RDONLY|O_NOCTTY|O_NOFOLLOW);
        if (new_fd < 0)
                goto do_rename;

        if (fstat(old_fd, &old_stat) < 0)
                goto do_rename;

        if (!S_ISREG(old_stat.st_mode))
                goto do_rename;

        if (fstat(new_fd, &new_stat) < 0)
                goto do_rename;

        if (new_stat.st_ino == old_stat.st_ino &&
            new_stat.st_dev == old_stat.st_dev)
                goto is_same;

        if (old_stat.st_mode != new_stat.st_mode ||
            old_stat.st_size != new_stat.st_size ||
            old_stat.st_uid != new_stat.st_uid ||
            old_stat.st_gid != new_stat.st_gid)
                goto do_rename;

        for (;;) {
                uint8_t buf1[16*1024];
                uint8_t buf2[sizeof(buf1)];
                ssize_t l1, l2;

                l1 = read(old_fd, buf1, sizeof(buf1));
                if (l1 < 0)
                        goto do_rename;

                if (l1 == sizeof(buf1))
                        /* Read the full block, hence read a full block in the other file too */

                        l2 = read(new_fd, buf2, l1);
                else {
                        assert((size_t) l1 < sizeof(buf1));

                        /* Short read. This hence was the last block in the first file, and then came
                         * EOF. Read one byte more in the second file, so that we can verify we hit EOF there
                         * too. */

                        assert((size_t) (l1 + 1) <= sizeof(buf2));
                        l2 = read(new_fd, buf2, l1 + 1);
                }
                if (l2 != l1)
                        goto do_rename;

                if (memcmp(buf1, buf2, l1) != 0)
                        goto do_rename;

                if ((size_t) l1 < sizeof(buf1)) /* We hit EOF on the first file, and the second file too, hence exit
                                                 * now. */
                        break;
        }

is_same:
        /* Everything matches? Then don't rename, instead remove the source file, and leave the existing
         * destination in place */

        if (unlinkat(olddirfd, oldpath, 0) < 0)
                goto do_rename;

        return 0;

do_rename:
        if (renameat(olddirfd, oldpath, newdirfd, newpath) < 0)
                return -errno;

        return 1;
}
