/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/mman.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "macro.h"
#include "memfd-util.h"
#include "missing_fcntl.h"
#include "missing_syscall.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "umask-util.h"

int fopen_temporary(const char *path, FILE **ret_f, char **ret_temp_path) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *t = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        if (path) {
                r = tempfn_xxxxxx(path, NULL, &t);
                if (r < 0)
                        return r;
        } else {
                const char *d;

                r = tmp_dir(&d);
                if (r < 0)
                        return r;

                t = path_join(d, "XXXXXX");
                if (!t)
                        return -ENOMEM;
        }

        fd = mkostemp_safe(t);
        if (fd < 0)
                return -errno;

        /* This assumes that returned FILE object is short-lived and used within the same single-threaded
         * context and never shared externally, hence locking is not necessary. */

        r = take_fdopen_unlocked(&fd, "w", &f);
        if (r < 0) {
                (void) unlink(t);
                return r;
        }

        if (ret_f)
                *ret_f = TAKE_PTR(f);

        if (ret_temp_path)
                *ret_temp_path = TAKE_PTR(t);

        return 0;
}

/* This is much like mkostemp() but is subject to umask(). */
int mkostemp_safe(char *pattern) {
        int fd = -1; /* avoid false maybe-uninitialized warning */

        assert(pattern);

        RUN_WITH_UMASK(0077)
                fd = mkostemp(pattern, O_CLOEXEC);
        if (fd < 0)
                return -errno;

        return fd;
}

int fmkostemp_safe(char *pattern, const char *mode, FILE **ret_f) {
        _cleanup_close_ int fd = -1;
        FILE *f;

        fd = mkostemp_safe(pattern);
        if (fd < 0)
                return fd;

        f = take_fdopen(&fd, mode);
        if (!f)
                return -errno;

        *ret_f = f;
        return 0;
}

int tempfn_xxxxxx(const char *p, const char *extra, char **ret) {
        _cleanup_free_ char *d = NULL, *fn = NULL, *nf = NULL;
        int r;

        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#<extra>waldoXXXXXX
         */

        r = path_extract_directory(p, &d);
        if (r < 0 && r != -EDESTADDRREQ) /* EDESTADDRREQ → No directory specified, just a filename */
                return r;

        r = path_extract_filename(p, &fn);
        if (r < 0)
                return r;

        nf = strjoin(".#", strempty(extra), fn, "XXXXXX");
        if (!nf)
                return -ENOMEM;

        if (!filename_is_valid(nf)) /* New name is not valid? (Maybe because too long?) Refuse. */
                return -EINVAL;

        if (d)  {
                char *j;

                j = path_join(d, nf);
                if (!j)
                        return -ENOMEM;

                *ret = path_simplify(j, false);
        } else
                *ret = TAKE_PTR(nf);

        return 0;
}

int tempfn_random(const char *p, const char *extra, char **ret) {
        _cleanup_free_ char *d = NULL, *fn = NULL, *nf = NULL;
        int r;

        assert(ret);

        /*
         * Turns this:
         *         /foo/bar/waldo
         *
         * Into this:
         *         /foo/bar/.#<extra>waldobaa2a261115984a9
         */

        r = path_extract_directory(p, &d);
        if (r < 0 && r != -EDESTADDRREQ) /* EDESTADDRREQ → No directory specified, just a filename */
                return r;

        r = path_extract_filename(p, &fn);
        if (r < 0)
                return r;

        if (asprintf(&nf, ".#%s%s%016" PRIx64,
                     strempty(extra),
                     fn,
                     random_u64()) < 0)
                return -ENOMEM;

        if (!filename_is_valid(nf)) /* Not valid? (maybe because too long now?) — refuse early */
                return -EINVAL;

        if (d) {
                char *j;

                j = path_join(d, nf);
                if (!j)
                        return -ENOMEM;

                *ret = path_simplify(j, false);
        } else
                *ret = TAKE_PTR(nf);

        return 0;
}

int tempfn_random_child(const char *p, const char *extra, char **ret) {
        char *t, *x;
        uint64_t u;
        int r;

        assert(ret);

        /* Turns this:
         *         /foo/bar/waldo
         * Into this:
         *         /foo/bar/waldo/.#<extra>3c2b6219aa75d7d0
         */

        if (!p) {
                r = tmp_dir(&p);
                if (r < 0)
                        return r;
        }

        extra = strempty(extra);

        t = new(char, strlen(p) + 3 + strlen(extra) + 16 + 1);
        if (!t)
                return -ENOMEM;

        if (isempty(p))
                x = stpcpy(stpcpy(t, ".#"), extra);
        else
                x = stpcpy(stpcpy(stpcpy(t, p), "/.#"), extra);

        u = random_u64();
        for (unsigned i = 0; i < 16; i++) {
                *(x++) = hexchar(u & 0xF);
                u >>= 4;
        }

        *x = 0;

        *ret = path_simplify(t, false);
        return 0;
}

int open_tmpfile_unlinkable(const char *directory, int flags) {
        char *p;
        int fd, r;

        if (!directory) {
                r = tmp_dir(&directory);
                if (r < 0)
                        return r;
        } else if (isempty(directory))
                return -EINVAL;

        /* Returns an unlinked temporary file that cannot be linked into the file system anymore */

        /* Try O_TMPFILE first, if it is supported */
        fd = open(directory, flags|O_TMPFILE|O_EXCL, S_IRUSR|S_IWUSR);
        if (fd >= 0)
                return fd;

        /* Fall back to unguessable name + unlinking */
        p = strjoina(directory, "/systemd-tmp-XXXXXX");

        fd = mkostemp_safe(p);
        if (fd < 0)
                return fd;

        (void) unlink(p);

        return fd;
}

int open_tmpfile_linkable(const char *target, int flags, char **ret_path) {
        _cleanup_free_ char *tmp = NULL;
        int r, fd;

        assert(target);
        assert(ret_path);

        /* Don't allow O_EXCL, as that has a special meaning for O_TMPFILE */
        assert((flags & O_EXCL) == 0);

        /* Creates a temporary file, that shall be renamed to "target" later. If possible, this uses O_TMPFILE – in
         * which case "ret_path" will be returned as NULL. If not possible the temporary path name used is returned in
         * "ret_path". Use link_tmpfile() below to rename the result after writing the file in full. */

        fd = open_parent(target, O_TMPFILE|flags, 0640);
        if (fd >= 0) {
                *ret_path = NULL;
                return fd;
        }

        log_debug_errno(fd, "Failed to use O_TMPFILE for %s: %m", target);

        r = tempfn_random(target, NULL, &tmp);
        if (r < 0)
                return r;

        fd = open(tmp, O_CREAT|O_EXCL|O_NOFOLLOW|O_NOCTTY|flags, 0640);
        if (fd < 0)
                return -errno;

        *ret_path = TAKE_PTR(tmp);

        return fd;
}

int link_tmpfile(int fd, const char *path, const char *target) {
        int r;

        assert(fd >= 0);
        assert(target);

        /* Moves a temporary file created with open_tmpfile() above into its final place. if "path" is NULL an fd
         * created with O_TMPFILE is assumed, and linkat() is used. Otherwise it is assumed O_TMPFILE is not supported
         * on the directory, and renameat2() is used instead.
         *
         * Note that in both cases we will not replace existing files. This is because linkat() does not support this
         * operation currently (renameat2() does), and there is no nice way to emulate this. */

        if (path) {
                r = rename_noreplace(AT_FDCWD, path, AT_FDCWD, target);
                if (r < 0)
                        return r;
        } else {
                char proc_fd_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(fd) + 1];

                xsprintf(proc_fd_path, "/proc/self/fd/%i", fd);

                if (linkat(AT_FDCWD, proc_fd_path, AT_FDCWD, target, AT_SYMLINK_FOLLOW) < 0)
                        return -errno;
        }

        return 0;
}

int mkdtemp_malloc(const char *template, char **ret) {
        _cleanup_free_ char *p = NULL;
        int r;

        assert(ret);

        if (template)
                p = strdup(template);
        else {
                const char *tmp;

                r = tmp_dir(&tmp);
                if (r < 0)
                        return r;

                p = path_join(tmp, "XXXXXX");
        }
        if (!p)
                return -ENOMEM;

        if (!mkdtemp(p))
                return -errno;

        *ret = TAKE_PTR(p);
        return 0;
}
