/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <linux/falloc.h>
#include <linux/magic.h>
#include <unistd.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hostname-util.h"
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
#include "ratelimit.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"
#include "user-util.h"
#include "util.h"

int unlink_noerrno(const char *path) {
        PROTECT_ERRNO;
        return RET_NERRNO(unlink(path));
}

int rmdir_parents(const char *path, const char *stop) {
        char *p;
        int r;

        assert(path);
        assert(stop);

        if (!path_is_safe(path))
                return -EINVAL;

        if (!path_is_safe(stop))
                return -EINVAL;

        p = strdupa_safe(path);

        for (;;) {
                char *slash = NULL;

                /* skip the last component. */
                r = path_find_last_component(p, /* accept_dot_dot= */ false, (const char **) &slash, NULL);
                if (r <= 0)
                        return r;
                if (slash == p)
                        return 0;

                assert(*slash == '/');
                *slash = '\0';

                if (path_startswith_full(stop, p, /* accept_dot_dot= */ false))
                        return 0;

                if (rmdir(p) < 0 && errno != ENOENT)
                        return -errno;
        }
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

                r = RET_NERRNO(unlinkat(olddirfd, oldpath, 0));
                if (r < 0) {
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

        return RET_NERRNO(renameat(olddirfd, oldpath, newdirfd, newpath));
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

int fchmod_and_chown_with_fallback(int fd, const char *path, mode_t mode, uid_t uid, gid_t gid) {
        bool do_chown, do_chmod;
        struct stat st;
        int r;

        /* Change ownership and access mode of the specified fd. Tries to do so safely, ensuring that at no
         * point in time the access mode is above the old access mode under the old ownership or the new
         * access mode under the new ownership. Note: this call tries hard to leave the access mode
         * unaffected if the uid/gid is changed, i.e. it undoes implicit suid/sgid dropping the kernel does
         * on chown().
         *
         * This call is happy with O_PATH fds.
         *
         * If path is given, allow a fallback path which does not use /proc/self/fd/. On any normal system
         * /proc will be mounted, but in certain improperly assembled environments it might not be. This is
         * less secure (potential TOCTOU), so should only be used after consideration. */

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
                        if (r < 0) {
                                if (!path || r != -ENOSYS)
                                        return r;

                                /* Fallback path which doesn't use /proc/self/fd/. */
                                if (chmod(path, minimal & 07777) < 0)
                                        return -errno;
                        }
                }
        }

        if (do_chown)
                if (fchownat(fd, "", uid, gid, AT_EMPTY_PATH) < 0)
                        return -errno;

        if (do_chmod) {
                r = fchmod_opath(fd, mode & 07777);
                if (r < 0) {
                        if (!path || r != -ENOSYS)
                                return r;

                        /* Fallback path which doesn't use /proc/self/fd/. */
                        if (chmod(path, mode & 07777) < 0)
                                return -errno;
                }
        }

        return do_chown || do_chmod;
}

int fchmod_umask(int fd, mode_t m) {
        _cleanup_umask_ mode_t u = umask(0777);

        return RET_NERRNO(fchmod(fd, m & (~u)));
}

int fchmod_opath(int fd, mode_t m) {
        /* This function operates also on fd that might have been opened with
         * O_PATH. Indeed fchmodat() doesn't have the AT_EMPTY_PATH flag like
         * fchownat() does. */

        if (chmod(FORMAT_PROC_FD_PATH(fd), m) < 0) {
                if (errno != ENOENT)
                        return -errno;

                if (proc_mounted() == 0)
                        return -ENOSYS; /* if we have no /proc/, the concept is not implementable */

                return -ENOENT;
        }

        return 0;
}

int futimens_opath(int fd, const struct timespec ts[2]) {
        /* Similar to fchmod_path() but for futimens() */

        if (utimensat(AT_FDCWD, FORMAT_PROC_FD_PATH(fd), ts, 0) < 0) {
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
        _cleanup_close_ int fd = -1;
        int r, ret;

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
        ret = fchmod_and_chown(fd, mode, uid, gid);

        if (stamp != USEC_INFINITY) {
                struct timespec ts[2];

                timespec_store(&ts[0], stamp);
                ts[1] = ts[0];
                r = futimens_opath(fd, ts);
        } else
                r = futimens_opath(fd, NULL);
        if (r < 0 && ret >= 0)
                return r;

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
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_closedir_ DIR *d = NULL;
        size_t n = 0;

        assert(path);

        /* Returns all files in a directory in *list, and the number
         * of files as return value. If list is NULL returns only the
         * number. */

        d = opendir(path);
        if (!d)
                return -errno;

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                if (!dirent_is_file(de))
                        continue;

                if (list) {
                        /* one extra slot is needed for the terminating NULL */
                        if (!GREEDY_REALLOC(l, n + 2))
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

int access_fd(int fd, int mode) {
        /* Like access() but operates on an already open fd */

        if (access(FORMAT_PROC_FD_PATH(fd), mode) < 0) {
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

int open_parent(const char *path, int flags, mode_t mode) {
        _cleanup_free_ char *parent = NULL;
        int r;

        r = path_extract_directory(path, &parent);
        if (r < 0)
                return r;

        /* Let's insist on O_DIRECTORY since the parent of a file or directory is a directory. Except if we open an
         * O_TMPFILE file, because in that case we are actually create a regular file below the parent directory. */

        if (FLAGS_SET(flags, O_PATH))
                flags |= O_DIRECTORY;
        else if (!FLAGS_SET(flags, O_TMPFILE))
                flags |= O_DIRECTORY|O_RDONLY;

        return RET_NERRNO(open(parent, flags, mode));
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

        if (stat_inode_same(&new_stat, &old_stat))
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

int posix_fallocate_loop(int fd, uint64_t offset, uint64_t size) {
        RateLimit rl;
        int r;

        r = posix_fallocate(fd, offset, size); /* returns positive errnos on error */
        if (r != EINTR)
                return -r; /* Let's return negative errnos, like common in our codebase */

        /* On EINTR try a couple of times more, but protect against busy looping
         * (not more than 16 times per 10s) */
        rl = (RateLimit) { 10 * USEC_PER_SEC, 16 };
        while (ratelimit_below(&rl)) {
                r = posix_fallocate(fd, offset, size);
                if (r != EINTR)
                        return -r;
        }

        return -EINTR;
}

int parse_cifs_service(
                const char *s,
                char **ret_host,
                char **ret_service,
                char **ret_path) {

        _cleanup_free_ char *h = NULL, *ss = NULL, *x = NULL;
        const char *p, *e, *d;
        char delimiter;

        /* Parses a CIFS service in form of //host/service/path… and splitting it in three parts. The last
         * part is optional, in which case NULL is returned there. To maximize compatibility syntax with
         * backslashes instead of slashes is accepted too. */

        if (!s)
                return -EINVAL;

        p = startswith(s, "//");
        if (!p) {
                p = startswith(s, "\\\\");
                if (!p)
                        return -EINVAL;
        }

        delimiter = s[0];
        e = strchr(p, delimiter);
        if (!e)
                return -EINVAL;

        h = strndup(p, e - p);
        if (!h)
                return -ENOMEM;

        if (!hostname_is_valid(h, 0))
                return -EINVAL;

        e++;

        d = strchrnul(e, delimiter);

        ss = strndup(e, d - e);
        if (!ss)
                return -ENOMEM;

        if (!filename_is_valid(ss))
                return -EINVAL;

        if (!isempty(d)) {
                x = strdup(skip_leading_chars(d, CHAR_TO_STR(delimiter)));
                if (!x)
                        return -EINVAL;

                /* Make sure to convert Windows-style "\" → Unix-style / */
                for (char *i = x; *i; i++)
                        if (*i == delimiter)
                                *i = '/';

                if (!path_is_valid(x))
                        return -EINVAL;

                path_simplify(x);
                if (!path_is_normalized(x))
                        return -EINVAL;
        }

        if (ret_host)
                *ret_host = TAKE_PTR(h);
        if (ret_service)
                *ret_service = TAKE_PTR(ss);
        if (ret_path)
                *ret_path = TAKE_PTR(x);

        return 0;
}

int open_mkdir_at(int dirfd, const char *path, int flags, mode_t mode) {
        _cleanup_close_ int fd = -1, parent_fd = -1;
        _cleanup_free_ char *fname = NULL;
        bool made;
        int r;

        /* Creates a directory with mkdirat() and then opens it, in the "most atomic" fashion we can
         * do. Guarantees that the returned fd refers to a directory. If O_EXCL is specified will fail if the
         * dir already exists. Otherwise will open an existing dir, but only if it is one.  */

        if (flags & ~(O_RDONLY|O_CLOEXEC|O_DIRECTORY|O_EXCL|O_NOATIME|O_NOFOLLOW|O_PATH))
                return -EINVAL;
        if ((flags & O_ACCMODE) != O_RDONLY)
                return -EINVAL;

        /* Note that O_DIRECTORY|O_NOFOLLOW is implied, but we allow specifying it anyway. The following
         * flags actually make sense to specify: O_CLOEXEC, O_EXCL, O_NOATIME, O_PATH */

        if (isempty(path))
                return -EINVAL;

        if (!filename_is_valid(path)) {
                _cleanup_free_ char *parent = NULL;

                /* If this is not a valid filename, it's a path. Let's open the parent directory then, so
                 * that we can pin it, and operate below it. */

                r = path_extract_directory(path, &parent);
                if (r < 0)
                        return r;

                r = path_extract_filename(path, &fname);
                if (r < 0)
                        return r;

                parent_fd = openat(dirfd, parent, O_PATH|O_DIRECTORY|O_CLOEXEC);
                if (parent_fd < 0)
                        return -errno;

                dirfd = parent_fd;
                path = fname;
        }

        r = RET_NERRNO(mkdirat(dirfd, path, mode));
        if (r == -EEXIST) {
                if (FLAGS_SET(flags, O_EXCL))
                        return -EEXIST;

                made = false;
        } else if (r < 0)
                return r;
        else
                made = true;

        fd = RET_NERRNO(openat(dirfd, path, (flags & ~O_EXCL)|O_DIRECTORY|O_NOFOLLOW));
        if (fd < 0) {
                if (fd == -ENOENT)  /* We got ENOENT? then someone else immediately removed it after we
                                     * created it. In that case let's return immediately without unlinking
                                     * anything, because there simply isn't anything to unlink anymore. */
                        return -ENOENT;
                if (fd == -ELOOP)   /* is a symlink? exists already → created by someone else, don't unlink */
                        return -EEXIST;
                if (fd == -ENOTDIR) /* not a directory? exists already → created by someone else, don't unlink */
                        return -EEXIST;

                if (made)
                        (void) unlinkat(dirfd, path, AT_REMOVEDIR);

                return fd;
        }

        return TAKE_FD(fd);
}

int openat_report_new(int dirfd, const char *pathname, int flags, mode_t mode, bool *ret_newly_created) {
        unsigned attempts = 7;
        int fd;

        /* Just like openat(), but adds one thing: optionally returns whether we created the file anew or if
         * it already existed before. This is only relevant if O_CREAT is set without O_EXCL, and thus will
         * shortcut to openat() otherwise */

        if (!ret_newly_created)
                return RET_NERRNO(openat(dirfd, pathname, flags, mode));

        if (!FLAGS_SET(flags, O_CREAT) || FLAGS_SET(flags, O_EXCL)) {
                fd = openat(dirfd, pathname, flags, mode);
                if (fd < 0)
                        return -errno;

                *ret_newly_created = FLAGS_SET(flags, O_CREAT);
                return fd;
        }

        for (;;) {
                /* First, attempt to open without O_CREAT/O_EXCL, i.e. open existing file */
                fd = openat(dirfd, pathname, flags & ~(O_CREAT | O_EXCL), mode);
                if (fd >= 0) {
                        *ret_newly_created = false;
                        return fd;
                }
                if (errno != ENOENT)
                        return -errno;

                /* So the file didn't exist yet, hence create it with O_CREAT/O_EXCL. */
                fd = openat(dirfd, pathname, flags | O_CREAT | O_EXCL, mode);
                if (fd >= 0) {
                        *ret_newly_created = true;
                        return fd;
                }
                if (errno != EEXIST)
                        return -errno;

                /* Hmm, so now we got EEXIST? So it apparently exists now? If so, let's try to open again
                 * without the two flags. But let's not spin forever, hence put a limit on things */

                if (--attempts == 0) /* Give up eventually, somebody is playing with us */
                        return -EEXIST;
        }
}
