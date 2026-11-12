/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chattr-util.h"
#include "chase.h"
#include "cleanup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iref.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "xattr-util.h"

#define IREF_OPEN_FLAGS \
        (IREF_WRONLY|IREF_RDWR|IREF_PATH|IREF_DIRECTORY|IREF_NOFOLLOW|IREF_CREAT|IREF_EXCL|IREF_TRUNC| \
         IREF_APPEND|IREF_NONBLOCK|IREF_NOCTTY|IREF_DSYNC|IREF_SYNC|IREF_DIRECT|IREF_NOATIME|IREF_ASYNC|IREF_TMPFILE)

#define IREF_LOOKUP_FLAGS \
        (IREF_DIRECTORY|IREF_REGULAR|IREF_SOCKET|IREF_NOFOLLOW|IREF_NONEXISTENT|IREF_NO_AUTOFS| \
         IREF_TRIGGER_AUTOFS|IREF_SAFE|IREF_STEP|IREF_WARN|IREF_PROHIBIT_SYMLINKS|IREF_PARENT| \
         IREF_MKDIR_0755|IREF_EXTRACT_FILENAME_HARDER|IREF_MAX_MODE|IREF_NO_SYNC)

#define IREF_XOPEN_FLAGS \
        (IREF_LABEL|IREF_SUBVOLUME|IREF_NOCOW|IREF_COW|IREF_AUTO_RW_RO)

#define IREF_UNSUPPORTED_LOOKUP_FLAGS \
        (IREF_NONEXISTENT|IREF_STEP|IREF_PARENT|IREF_EXTRACT_FILENAME)

#define IREF_PATH_ROOT ((char*) POINTER_MAX)

static const struct {
        IRefFlags flag;
        int open_flags;
        ChaseFlags chase_flags;
        XOpenFlags xopen_flags;
} iref_flag_map[] = {
        { IREF_WRONLY,                  O_WRONLY,    0,                             0                    },
        { IREF_RDWR,                    O_RDWR,      0,                             0                    },
        { IREF_PATH,                    O_PATH,      0,                             0                    },
        { IREF_DIRECTORY,               O_DIRECTORY, CHASE_MUST_BE_DIRECTORY,       0                    },
        { IREF_REGULAR,                 0,           CHASE_MUST_BE_REGULAR,         XO_REGULAR           },
        { IREF_SOCKET,                  0,           CHASE_MUST_BE_SOCKET,          XO_SOCKET            },
        { IREF_NOFOLLOW,                O_NOFOLLOW,  CHASE_NOFOLLOW,                0                    },
        { IREF_CREAT,                   O_CREAT,     0,                             0                    },
        { IREF_EXCL,                    O_EXCL,      0,                             0                    },
        { IREF_TRUNC,                   O_TRUNC,     0,                             0                    },
        { IREF_APPEND,                  O_APPEND,    0,                             0                    },
        { IREF_NONBLOCK,                O_NONBLOCK,  0,                             0                    },
        { IREF_NOCTTY,                  O_NOCTTY,    0,                             0                    },
        { IREF_DSYNC,                   O_DSYNC,     0,                             0                    },
        { IREF_SYNC,                    O_SYNC,      0,                             0                    },
        { IREF_DIRECT,                  O_DIRECT,    0,                             0                    },
        { IREF_NOATIME,                 O_NOATIME,   0,                             0                    },
        { IREF_ASYNC,                   O_ASYNC,     0,                             0                    },
        { IREF_TMPFILE,                 O_TMPFILE,   0,                             0                    },
        { IREF_NONEXISTENT,             0,           CHASE_NONEXISTENT,             0                    },
        { IREF_NO_AUTOFS,               0,           CHASE_NO_AUTOFS,               0                    },
        { IREF_TRIGGER_AUTOFS,          0,           CHASE_TRIGGER_AUTOFS,          XO_TRIGGER_AUTOMOUNT },
        { IREF_SAFE,                    0,           CHASE_SAFE,                    0                    },
        { IREF_STEP,                    0,           CHASE_STEP,                    0                    },
        { IREF_WARN,                    0,           CHASE_WARN,                    0                    },
        { IREF_PROHIBIT_SYMLINKS,       0,           CHASE_PROHIBIT_SYMLINKS,       0                    },
        { IREF_PARENT,                  0,           CHASE_PARENT,                  0                    },
        { IREF_MKDIR_0755,              0,           CHASE_MKDIR_0755,              0                    },
        { IREF_EXTRACT_FILENAME,        0,           CHASE_EXTRACT_FILENAME,        0                    },
        { IREF_EXTRACT_FILENAME_HARDER, 0,           CHASE_EXTRACT_FILENAME_HARDER, 0                    },
        { IREF_MAX_MODE,                0,           CHASE_MAX_MODE,                0                    },
        { IREF_NO_SYNC,                 0,           CHASE_NO_SYNC,                 XO_NO_SYNC           },
        { IREF_LABEL,                   0,           0,                             XO_LABEL             },
        { IREF_SUBVOLUME,               0,           0,                             XO_SUBVOLUME         },
        { IREF_NOCOW,                   0,           0,                             XO_NOCOW             },
        { IREF_COW,                     0,           0,                             XO_COW               },
        { IREF_AUTO_RW_RO,              0,           0,                             XO_AUTO_RW_RO        },
};

static void iref_flags_to_native(
                IRefFlags flags,
                int *ret_open_flags,
                ChaseFlags *ret_chase_flags,
                XOpenFlags *ret_xopen_flags) {
        int open_flags = 0;
        ChaseFlags chase_flags = CHASE_EMPTY_PATH;
        XOpenFlags xopen_flags = 0;

        assert(!(flags & ~(IREF_OPEN_FLAGS|IREF_LOOKUP_FLAGS|IREF_XOPEN_FLAGS)));

        FOREACH_ELEMENT(m, iref_flag_map)
                if (FLAGS_SET(flags, m->flag)) {
                        open_flags |= m->open_flags;
                        chase_flags |= m->chase_flags;
                        xopen_flags |= m->xopen_flags;
                }

        if (!FLAGS_SET(open_flags, O_PATH))
                xopen_flags &= ~XO_TRIGGER_AUTOMOUNT;

        if (ret_open_flags)
                *ret_open_flags = open_flags;
        if (ret_chase_flags)
                *ret_chase_flags = chase_flags;
        if (ret_xopen_flags)
                *ret_xopen_flags = xopen_flags;
}

struct IRef {
        unsigned n_ref;
        /* The fd may be an O_PATH or readable/writable descriptor. */
        int fd;
        /* The path is absolute within the root. IREF_PATH_ROOT represents "/", and an unnamed file has no
         * path. */
        char *path;
        /* Only a root iref from iref_open_root() sets root_path, to the resolved host path of the root
         * directory. */
        char *root_path;
        /* Paths are resolved under this root iref. It is NULL for a root iref itself. */
        IRef *root;
        /* A non-directory inode cannot open "..", so we retain the directory used to open it. */
        IRef *parent;
};

static IRef* iref_free(IRef *i) {
        if (!i)
                return NULL;

        safe_close(i->fd);
        if (i->path != IREF_PATH_ROOT)
                free(i->path);
        free(i->root_path);
        iref_unref(i->root);
        iref_unref(i->parent);

        return mfree(i);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(IRef, iref, iref_free);

static IRef* iref_root(IRef *i) {
        assert(i);

        return i->root ?: i;
}

static IRef* iref_root_ref(IRef *i) {
        return iref_ref(iref_root(i));
}

/* The caller donates fd and path on success. */
static int iref_new(int fd, char *path, IRef *root, IRef *parent, IRef **ret) {
        assert(fd >= 0);
        assert(path || parent);
        assert(ret);

        IRef *i = new(IRef, 1);
        if (!i)
                return -ENOMEM;

        *i = (IRef) {
                .n_ref = 1,
                .fd = fd,
                .path = path,
                .root = iref_ref(root),
                .parent = iref_ref(parent),
        };

        *ret = i;
        return 0;
}

int iref_open_root(const char *path, IRefFlags flags, IRef **ret) {
        ChaseFlags chase_flags;
        int open_flags, r;

        assert(path);
        assert(ret);
        assert(!(flags & ~(IREF_LOOKUP_FLAGS|IREF_PATH)));
        assert(!(flags & (IREF_UNSUPPORTED_LOOKUP_FLAGS|IREF_SOCKET)));

        iref_flags_to_native(flags|IREF_DIRECTORY, &open_flags, &chase_flags, /* ret_xopen_flags= */ NULL);

        _cleanup_free_ char *root_path = NULL;
        _cleanup_close_ int fd = chase_and_openat(XAT_FDROOT, XAT_FDROOT, path, chase_flags, open_flags, &root_path);
        if (fd < 0)
                return fd;

        r = iref_new(fd, IREF_PATH_ROOT, /* root= */ NULL, /* parent= */ NULL, ret);
        if (r < 0)
                return r;

        TAKE_FD(fd);
        (*ret)->root_path = TAKE_PTR(root_path);
        return 0;
}

int iref_open_root_fd(int fd, IRef **ret) {
        int r;

        assert(fd >= 0);
        assert(ret);

        r = fd_verify_directory(fd);
        if (r < 0)
                return r;

        _cleanup_close_ int copy = RET_NERRNO(fcntl(fd, F_DUPFD_CLOEXEC, 3));
        if (copy < 0)
                return copy;

        r = iref_new(copy, IREF_PATH_ROOT, /* root= */ NULL, /* parent= */ NULL, ret);
        if (r < 0)
                return r;

        TAKE_FD(copy);
        return 0;
}

int iref_fd(IRef *i) {
        assert(i);

        return i->fd;
}

int iref_is_host_root(IRef *i) {
        assert(i);

        return dir_fd_is_root(i->fd);
}

const char* iref_path(IRef *i) {
        assert(i);

        return i->path == IREF_PATH_ROOT ? "/" : i->path;
}

const char* iref_root_path(IRef *i) {
        return iref_root(i)->root_path;
}

/* chaseat() returns paths relative to the directory that the lookup of path started from. */
static int iref_make_absolute(IRef *i, const char *path, const char *result, char **ret) {
        return chaseat_make_absolute(result, path_is_absolute(path) ? "/" : iref_path(i), ret);
}

int iref_chase(IRef *i, const char *path, IRefFlags flags, char **ret) {
        ChaseFlags chase_flags;
        int r, status;

        assert(i);
        assert(path);
        assert(!(flags & ~IREF_LOOKUP_FLAGS));

        iref_flags_to_native(flags, /* ret_open_flags= */ NULL, &chase_flags, /* ret_xopen_flags= */ NULL);

        _cleanup_free_ char *p = NULL;
        status = chaseat(iref_fd(iref_root(i)),
                         iref_fd(i),
                         path,
                         chase_flags,
                         ret ? &p : NULL,
                         /* ret_fd= */ NULL);
        if (status < 0)
                return status;
        if (!ret)
                return status;
        if (!i->path && isempty(path))
                return -EADDRNOTAVAIL;

        if (FLAGS_SET(chase_flags, CHASE_EXTRACT_FILENAME))
                *ret = TAKE_PTR(p);
        else {
                r = iref_make_absolute(i, path, p, ret);
                if (r < 0)
                        return r;
        }

        return status;
}

int iref_open_parent(IRef *i, const char *path, IRefFlags flags, IRef **ret, char **ret_filename) {
        ChaseFlags chase_flags;
        int r;

        assert(i);
        assert(path);
        assert(ret);
        assert(!(flags & ~IREF_LOOKUP_FLAGS));
        assert(!(flags & IREF_UNSUPPORTED_LOOKUP_FLAGS));

        iref_flags_to_native(flags, /* ret_open_flags= */ NULL, &chase_flags, /* ret_xopen_flags= */ NULL);

        /* The MUST_BE flags describe the last component, and this function doesn't open it. CHASE_PARENT
         * already requires the parent to be a directory. */
        chase_flags &= ~(CHASE_MUST_BE_DIRECTORY|CHASE_MUST_BE_REGULAR|CHASE_MUST_BE_SOCKET);

        if (isempty(path)) {
                if (!i->path || !empty_or_root(iref_path(i))) {
                        assert(!(flags & ~(IREF_NOFOLLOW|IREF_DIRECTORY|IREF_REGULAR|IREF_SOCKET)));
                        return iref_parent_full(i, ret, ret_filename);
                }

                path = ".";
        }

        /* We chase without CHASE_EXTRACT_FILENAME, because we need the full path for the returned iref. */
        IRef *root = iref_root(i);
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int parent_fd = -EBADF;
        r = chaseat(iref_fd(root),
                    iref_fd(i),
                    path,
                    chase_flags|CHASE_PARENT|CHASE_TRAIL_SLASH,
                    &p,
                    &parent_fd);
        if (r < 0)
                return r;

        _cleanup_free_ char *dir_path = NULL, *fname = NULL;
        int open_flags = chase_split_prefix_filename(
                        p, /* root= */ NULL,
                        &dir_path,
                        ret_filename ? &fname : NULL);
        if (open_flags < 0)
                return open_flags;

        _cleanup_free_ char *full = NULL;
        r = iref_make_absolute(i, path, dir_path, &full);
        if (r < 0)
                return r;
        path_simplify(full);

        r = iref_new(parent_fd, full, root, /* parent= */ NULL, ret);
        if (r < 0)
                return r;

        TAKE_FD(parent_fd);
        TAKE_PTR(full);

        if (ret_filename)
                *ret_filename = TAKE_PTR(fname);
        return FLAGS_SET(open_flags, O_DIRECTORY);
}

int iref_open_full(IRef *i, const char *path, IRefFlags flags, mode_t mode, IRef **ret) {
        struct statx stx;
        ChaseFlags chase_flags;
        XOpenFlags xopen_flags;
        int open_flags, r;

        assert(i);
        assert(path);
        assert(ret);
        assert(!(flags & IREF_UNSUPPORTED_LOOKUP_FLAGS));

        if (FLAGS_SET(flags, IREF_CREAT)) {
                if (!(flags & (IREF_NOFOLLOW|IREF_EXCL)))
                        return -EINVAL;

                flags |= IREF_NOFOLLOW;
        }

        iref_flags_to_native(flags, &open_flags, &chase_flags, &xopen_flags);

        IRef *root = iref_root(i);
        if (FLAGS_SET(flags, IREF_TMPFILE)) {
                if (!(flags & (IREF_WRONLY|IREF_RDWR)) ||
                    (flags & (IREF_PATH|IREF_CREAT|IREF_DIRECTORY|IREF_SOCKET|IREF_LABEL|IREF_SUBVOLUME|
                              IREF_TRIGGER_AUTOFS|IREF_AUTO_RW_RO)))
                        return -EINVAL;

                _cleanup_(iref_unrefp) IRef *dir = NULL;
                r = iref_open(i,
                              path,
                              (flags & IREF_LOOKUP_FLAGS & ~IREF_REGULAR)|IREF_PATH|IREF_DIRECTORY,
                              &dir);
                if (r < 0)
                        return r;

                _cleanup_close_ int fd = xopenat_full(
                                dir->fd,
                                ".",
                                open_flags|O_NOFOLLOW,
                                xopen_flags & ~XO_REGULAR,
                                mode);
                if (fd < 0)
                        return fd;

                r = iref_new(fd, /* path= */ NULL, root, dir, ret);
                if (r < 0)
                        return r;

                TAKE_FD(fd);
                return 0;
        }

        if (isempty(path)) {
                if (FLAGS_SET(flags, IREF_CREAT))
                        return -EISDIR;

                _cleanup_close_ int fd = xopenat_full(
                                iref_fd(i),
                                /* path= */ NULL,
                                open_flags|O_NOFOLLOW,
                                xopen_flags|XO_EMPTY_PATH,
                                mode);
                if (fd < 0)
                        return fd;

                _cleanup_free_ char *full = NULL;
                if (i->path) {
                        full = strdup(iref_path(i));
                        if (!full)
                                return -ENOMEM;
                }

                r = iref_new(fd, full, root, i->parent, ret);
                if (r < 0)
                        return r;

                TAKE_FD(fd);
                TAKE_PTR(full);
                return 0;
        }

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *filename = NULL;
        r = iref_open_parent(i, path, flags & IREF_LOOKUP_FLAGS, &parent, &filename);
        if (r < 0)
                return r;

        _cleanup_free_ char *full = path_join(iref_path(parent), filename);
        if (!full)
                return -ENOMEM;

        path_simplify(full);

        const char *name = streq(filename, ".") ? NULL : filename;
        if (r > 0 || !name) {
                if (flags & (IREF_REGULAR|IREF_SOCKET))
                        return -EBADSLT;
                if (!name && FLAGS_SET(flags, IREF_CREAT))
                        return -EISDIR;

                open_flags |= O_DIRECTORY;
        }

        _cleanup_close_ int fd = xopenat_full(
                        parent->fd,
                        name,
                        open_flags|O_NOFOLLOW,
                        xopen_flags|XO_EMPTY_PATH,
                        mode);
        if (fd < 0)
                return fd;

        r = xstatx(fd,
                   /* path= */ NULL,
                   FLAGS_SET(chase_flags, CHASE_NO_SYNC) ? AT_STATX_DONT_SYNC : 0,
                   STATX_TYPE,
                   &stx);
        if (r < 0)
                return r;

        r = iref_new(fd, full, root, S_ISDIR(stx.stx_mode) ? NULL : parent, ret);
        if (r < 0)
                return r;

        TAKE_FD(fd);
        TAKE_PTR(full);
        return 0;
}

int iref_fopen_unlocked(IRef *i, const char *path, IRefFlags flags, const char *mode, FILE **ret) {
        IRefFlags mode_flags = 0;
        int open_flags, r;

        assert(i);
        assert(mode);
        assert(ret);
        assert(!(flags & ~IREF_LOOKUP_FLAGS));
        assert(!(flags & IREF_SOCKET));

        open_flags = fopen_mode_to_flags(mode);
        if (open_flags < 0)
                return open_flags;

        FOREACH_ELEMENT(m, iref_flag_map)
                if (m->open_flags != 0 && FLAGS_SET(open_flags, m->open_flags))
                        mode_flags |= m->flag;

        _cleanup_(iref_unrefp) IRef *f = NULL;
        r = iref_open(i, path, flags|mode_flags, &f);
        if (r < 0)
                return r;

        return take_fdopen_unlocked(&f->fd, mode, ret);
}

int iref_parent_full(IRef *i, IRef **ret, char **ret_filename) {
        int r;

        assert(i);
        assert(ret);

        if (ret_filename && !i->path)
                return -EADDRNOTAVAIL;

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        if (i->parent)
                parent = iref_ref(i->parent);
        else {
                /* iref_open() can create another reference to the root inode. The root guard must compare
                 * inode and mount identity. */
                r = fds_inode_and_mount_same(i->fd, iref_root(i)->fd);
                if (r < 0)
                        return r;
                if (r > 0)
                        return -EINVAL;

                r = iref_open(i, "..", IREF_PATH, &parent);
                if (r < 0)
                        return r;
        }

        _cleanup_free_ char *filename = NULL;
        if (ret_filename) {
                r = path_extract_filename(iref_path(i), &filename);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(parent);
        if (ret_filename)
                *ret_filename = TAKE_PTR(filename);
        return 0;
}

/* The directory entry that i was opened through might have been renamed or replaced since then. We check
 * that it still refers to the inode of i before we remove or rename it. Another process can still replace
 * the entry between the check and the unlinkat() or renameat2(), so the check narrows that window but
 * doesn't close it. */
static int iref_verify_entry(IRef *i, IRef **ret_parent, char **ret_filename) {
        int r;

        assert(i);
        assert(ret_parent);
        assert(ret_filename);

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *filename = NULL;
        r = iref_parent_full(i, &parent, &filename);
        if (r < 0)
                return r;

        r = inode_same_at(parent->fd, filename, i->fd, /* fileb= */ NULL, AT_EMPTY_PATH|AT_SYMLINK_NOFOLLOW);
        if (r < 0)
                return r;
        if (r == 0)
                return -ESTALE;

        *ret_parent = TAKE_PTR(parent);
        *ret_filename = TAKE_PTR(filename);
        return 0;
}

int iref_stat(IRef *i, struct stat *ret) {
        assert(i);
        assert(ret);

        return RET_NERRNO(fstat(i->fd, ret));
}

int iref_statx(IRef *i, int flags, unsigned mask, struct statx *ret) {
        assert(i);
        assert(ret);

        return xstatx(i->fd, /* path= */ NULL, flags|AT_EMPTY_PATH, mask, ret);
}

int iref_statfs(IRef *i, struct statfs *ret) {
        assert(i);
        assert(ret);

        return xstatfsat(i->fd, /* path= */ NULL, ret);
}

int iref_readlink(IRef *i, char **ret) {
        assert(i);
        assert(ret);

        return readlinkat_malloc(i->fd, "", ret);
}

int iref_opendir(IRef *i, DIR **ret) {
        assert(i);
        assert(ret);

        DIR *dir = xopendirat(i->fd, /* path= */ NULL, /* flags= */ 0);
        if (!dir)
                return -errno;

        *ret = dir;
        return 0;
}

int iref_getxattr(IRef *i, const char *name, char **ret, size_t *ret_size) {
        assert(i);

        return getxattr_at_malloc(i->fd, /* path= */ NULL, name, AT_EMPTY_PATH, ret, ret_size);
}

int iref_listxattr(IRef *i, char **ret) {
        assert(i);

        return listxattr_at_malloc(i->fd, /* path= */ NULL, AT_EMPTY_PATH, ret);
}

int iref_setxattr(
                IRef *i,
                const char *name,
                const char *value,
                size_t size,
                int flags) {

        assert(i);

        return xsetxattr_full(i->fd, /* path= */ NULL, AT_EMPTY_PATH, name, value, size, flags);
}

int iref_removexattr(IRef *i, const char *name) {
        assert(i);

        return xremovexattr(i->fd, /* path= */ NULL, AT_EMPTY_PATH, name);
}

int iref_chmod_and_chown(IRef *i, mode_t mode, uid_t uid, gid_t gid) {
        assert(i);

        return fchmod_and_chown(i->fd, mode, uid, gid);
}

int iref_utimens(IRef *i, const struct timespec times[2]) {
        assert(i);

        return futimens_opath(i->fd, times);
}

int iref_chattr(IRef *i, unsigned value, unsigned mask) {
        struct stat st;

        assert(i);

        if (fstat(i->fd, &st) < 0)
                return -errno;
        if (!inode_type_can_chattr(st.st_mode))
                return -ENOTTY;

        return chattr_fd(i->fd, value, mask);
}

int iref_access(IRef *i, const char *filename, int type) {
        assert(i);
        assert(isempty(filename) || filename_is_valid(filename) || streq_ptr(filename, "."));

        if (isempty(filename))
                return access_fd(i->fd, type);

        return RET_NERRNO(faccessat(i->fd, filename, type, AT_SYMLINK_NOFOLLOW));
}

int iref_fopen(IRef *i, const char *filename, IRefFlags flags, const char *mode, FILE **ret) {
        int open_flags;

        assert(i);
        assert(isempty(filename) || filename_is_valid(filename) || streq_ptr(filename, "."));
        assert(!(flags & ~IREF_OPEN_FLAGS));

        iref_flags_to_native(flags, &open_flags, /* ret_chase_flags= */ NULL, /* ret_xopen_flags= */ NULL);

        return xfopenat(i->fd, filename, mode, open_flags|O_NOFOLLOW, ret);
}

int iref_symlink(IRef *i, const char *target, const char *filename) {
        assert(i);
        assert(target);
        assert(filename_is_valid(filename) || streq_ptr(filename, "."));

        return RET_NERRNO(symlinkat(target, i->fd, filename));
}

int iref_mkdir(IRef *i, const char *filename, mode_t mode) {
        assert(i);
        assert(filename_is_valid(filename) || streq_ptr(filename, "."));

        return RET_NERRNO(mkdirat(i->fd, filename, mode));
}

int iref_mknod(IRef *i, const char *filename, mode_t mode, dev_t dev) {
        assert(i);
        assert(filename_is_valid(filename) || streq_ptr(filename, "."));

        return RET_NERRNO(mknodat(i->fd, filename, mode, dev));
}

int iref_mkfifo(IRef *i, const char *filename, mode_t mode) {
        assert(i);
        assert(filename_is_valid(filename) || streq_ptr(filename, "."));

        return RET_NERRNO(mkfifoat(i->fd, filename, mode));
}

int iref_link(IRef *i, IRef *to, const char *filename) {
        int r;

        assert(i);
        assert(to);
        assert(filename_is_valid(filename) || streq_ptr(filename, "."));

        if (!to->path)
                return -ENOTDIR;

        _cleanup_free_ char *new_path = NULL;
        if (!i->path) {
                new_path = path_join(iref_path(to), filename);
                if (!new_path)
                        return -ENOMEM;
        }

        r = link_fd(i->fd, to->fd, filename);
        if (r < 0)
                return r;

        if (!i->path) {
                i->path = TAKE_PTR(new_path);
                unref_and_replace_new_ref(i->parent, to, iref_ref, iref_unref);
                unref_and_replace_new_ref(i->root, to, iref_root_ref, iref_unref);
        }

        return 0;
}

int iref_unlink(IRef *i, const char *filename, int flags) {
        int r;

        assert(i);
        assert(isempty(filename) || filename_is_valid(filename) || streq_ptr(filename, "."));

        if (!isempty(filename))
                return RET_NERRNO(unlinkat(i->fd, filename, flags));

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *entry_filename = NULL;
        r = iref_verify_entry(i, &parent, &entry_filename);
        if (r < 0)
                return r;

        return RET_NERRNO(unlinkat(parent->fd, entry_filename, flags));
}

int iref_rename(IRef *from, const char *from_name, IRef *to, const char *to_name, unsigned flags) {
        int r;

        assert(from);
        assert(isempty(from_name) || filename_is_valid(from_name) || streq_ptr(from_name, "."));
        assert(to);
        assert(filename_is_valid(to_name) || streq_ptr(to_name, "."));

        if (!isempty(from_name))
                return RET_NERRNO(renameat2(from->fd, from_name, to->fd, to_name, flags));

        _cleanup_(iref_unrefp) IRef *from_parent = NULL;
        _cleanup_free_ char *from_filename = NULL;
        r = iref_verify_entry(from, &from_parent, &from_filename);
        if (r < 0)
                return r;

        _cleanup_free_ char *new_path = path_join(iref_path(to), to_name);
        if (!new_path)
                return -ENOMEM;

        r = RET_NERRNO(renameat2(from_parent->fd, from_filename, to->fd, to_name, flags));
        if (r < 0)
                return r;

        free_and_replace(from->path, new_path);

        if (from->parent)
                unref_and_replace_new_ref(from->parent, to, iref_ref, iref_unref);

        /* iref_verify_entry() refuses the root directory, so from isn't a root iref and from->root is its
         * root. */
        unref_and_replace_new_ref(from->root, to, iref_root_ref, iref_unref);

        return 0;
}
