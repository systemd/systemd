/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "cleanup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "iref.h"
#include "path-util.h"
#include "stat-util.h"
#include "string-util.h"

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

static void iref_flags_to_native(
                IRefFlags flags,
                int *ret_open_flags,
                ChaseFlags *ret_chase_flags,
                XOpenFlags *ret_xopen_flags) {
        static const struct {
                IRefFlags flag;
                int open_flags;
                ChaseFlags chase_flags;
                XOpenFlags xopen_flags;
        } map[] = {
                { IREF_WRONLY,            O_WRONLY,    0,                       0                    },
                { IREF_RDWR,              O_RDWR,      0,                       0                    },
                { IREF_PATH,              O_PATH,      0,                       0                    },
                { IREF_DIRECTORY,         O_DIRECTORY, CHASE_MUST_BE_DIRECTORY, 0                    },
                { IREF_REGULAR,           0,           CHASE_MUST_BE_REGULAR,   XO_REGULAR           },
                { IREF_SOCKET,            0,           CHASE_MUST_BE_SOCKET,    XO_SOCKET            },
                { IREF_NOFOLLOW,          O_NOFOLLOW,  CHASE_NOFOLLOW,          0                    },
                { IREF_CREAT,             O_CREAT,     0,                       0                    },
                { IREF_EXCL,              O_EXCL,      0,                       0                    },
                { IREF_TRUNC,             O_TRUNC,     0,                       0                    },
                { IREF_APPEND,            O_APPEND,    0,                       0                    },
                { IREF_NONBLOCK,          O_NONBLOCK,  0,                       0                    },
                { IREF_NOCTTY,            O_NOCTTY,    0,                       0                    },
                { IREF_DSYNC,             O_DSYNC,     0,                       0                    },
                { IREF_SYNC,              O_SYNC,      0,                       0                    },
                { IREF_DIRECT,            O_DIRECT,    0,                       0                    },
                { IREF_NOATIME,           O_NOATIME,   0,                       0                    },
                { IREF_ASYNC,             O_ASYNC,     0,                       0                    },
                { IREF_TMPFILE,           O_TMPFILE,   0,                       0                    },
                { IREF_NONEXISTENT,       0,           CHASE_NONEXISTENT,       0                    },
                { IREF_NO_AUTOFS,         0,           CHASE_NO_AUTOFS,         0                    },
                { IREF_TRIGGER_AUTOFS,    0,           CHASE_TRIGGER_AUTOFS,    XO_TRIGGER_AUTOMOUNT },
                { IREF_SAFE,              0,           CHASE_SAFE,              0                    },
                { IREF_STEP,              0,           CHASE_STEP,              0                    },
                { IREF_WARN,              0,           CHASE_WARN,              0                    },
                { IREF_PROHIBIT_SYMLINKS, 0,           CHASE_PROHIBIT_SYMLINKS, 0                    },
                { IREF_PARENT,            0,           CHASE_PARENT,            0                    },
                { IREF_MKDIR_0755,        0,           CHASE_MKDIR_0755,        0                    },
                { IREF_EXTRACT_FILENAME,  0,           CHASE_EXTRACT_FILENAME,  0                    },
                { IREF_MAX_MODE,          0,           CHASE_MAX_MODE,          0                    },
                { IREF_NO_SYNC,           0,           CHASE_NO_SYNC,           0                    },
                { IREF_LABEL,             0,           0,                       XO_LABEL             },
                { IREF_SUBVOLUME,         0,           0,                       XO_SUBVOLUME         },
                { IREF_NOCOW,             0,           0,                       XO_NOCOW             },
                { IREF_COW,               0,           0,                       XO_COW               },
                { IREF_AUTO_RW_RO,        0,           0,                       XO_AUTO_RW_RO        },
                { IREF_EXTRACT_FILENAME_HARDER, 0,     CHASE_EXTRACT_FILENAME_HARDER, 0                },
        };
        int open_flags = 0;
        ChaseFlags chase_flags = CHASE_EMPTY_PATH;
        XOpenFlags xopen_flags = 0;

        assert(!(flags & ~(IREF_OPEN_FLAGS|IREF_LOOKUP_FLAGS|IREF_XOPEN_FLAGS)));

        FOREACH_ELEMENT(m, map)
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
        int fd;
        /* The path is absolute and relative to the root, or to the host root if there is no root. A root
         * iref has the path "/". */
        char *path;
        /* Only a root iref sets root_path, to the resolved host path of the root directory. */
        char *root_path;
        /* Paths are resolved under this root iref. It is NULL if there is no root, and for a root iref
         * itself. */
        IRef *root;
        /* A non-directory inode cannot open "..", so we retain the directory used to open it. */
        IRef *parent;
};

static IRef* iref_free(IRef *i) {
        if (!i)
                return NULL;

        safe_close(i->fd);
        free(i->path);
        free(i->root_path);
        iref_unref(i->root);
        iref_unref(i->parent);

        return mfree(i);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(IRef, iref, iref_free);

static IRef* iref_root(IRef *i) {
        if (!i)
                return NULL;

        return i->root_path ? i : i->root;
}

static int iref_new(int *fd, char **path, IRef *root, IRef *parent, IRef **ret) {
        assert(fd);
        assert(*fd >= 0);
        assert(path);
        assert(*path);
        assert(ret);

        IRef *i = new(IRef, 1);
        if (!i)
                return -ENOMEM;

        *i = (IRef) {
                .n_ref = 1,
                .fd = TAKE_FD(*fd),
                .path = TAKE_PTR(*path),
                .root = iref_ref(root),
                .parent = iref_ref(parent),
        };

        *ret = i;
        return 0;
}

int iref_open_root(const char *path, IRefFlags flags, IRef **ret) {
        int r;

        assert(path);
        assert(ret);

        _cleanup_(iref_unrefp) IRef *i = NULL;
        r = iref_open(NULL, path, flags|IREF_DIRECTORY, &i);
        if (r < 0)
                return r;

        /* Nothing refers to i yet, so we can still turn it into a root. */
        char *p = strdup("/");
        if (!p)
                return -ENOMEM;

        i->root_path = TAKE_PTR(i->path);
        i->path = p;

        *ret = TAKE_PTR(i);
        return 0;
}

int iref_fd(const IRef *i) {
        return i ? i->fd : XAT_FDROOT;
}

int iref_is_root(const IRef *i) {
        assert(i);

        return dir_fd_is_root(i->fd);
}

const char* iref_path(const IRef *i) {
        assert(i);

        return i->path;
}

const char* iref_root_path(const IRef *i) {
        assert(i);

        const IRef *root = i->root_path ? i : i->root;
        return root ? root->root_path : "/";
}

/* iref_open_parent() returns "." as the filename if the path resolves to the root directory. mkdirat(),
 * unlinkat(), and renameat2() refuse ".", so iref_mkdir(), iref_unlink(), and iref_rename() accept it and
 * return the error of the system call. */
static bool iref_filename_is_valid(const char *filename) {
        return filename_is_valid(filename) || streq_ptr(filename, ".");
}

int iref_chase(IRef *i, const char *path, IRefFlags flags, char **ret) {
        ChaseFlags chase_flags;
        int r, status;

        assert(path);
        assert(!(flags & ~IREF_LOOKUP_FLAGS));

        iref_flags_to_native(flags, /* ret_open_flags= */ NULL, &chase_flags, /* ret_xopen_flags= */ NULL);

        _cleanup_free_ char *p = NULL;
        status = chaseat(iref_fd(iref_root(i)), iref_fd(i), path, chase_flags, ret ? &p : NULL, /* ret_fd= */ NULL);
        if (status < 0)
                return status;
        if (!ret)
                return status;

        if (FLAGS_SET(chase_flags, CHASE_EXTRACT_FILENAME))
                *ret = TAKE_PTR(p);
        else {
                r = chaseat_make_absolute(p, i && !path_is_absolute(path) ? i->path : "/", ret);
                if (r < 0)
                        return r;
        }

        return status;
}

int iref_open_parent(IRef *i, const char *path, IRefFlags flags, IRef **ret, char **ret_filename) {
        ChaseFlags chase_flags;
        int r;

        assert(path);
        assert(ret);
        assert(!(flags & ~IREF_LOOKUP_FLAGS));
        assert(!(flags & IREF_UNSUPPORTED_LOOKUP_FLAGS));

        iref_flags_to_native(flags, /* ret_open_flags= */ NULL, &chase_flags, /* ret_xopen_flags= */ NULL);

        /* The MUST_BE flags describe the last component, and this function doesn't open it. CHASE_PARENT
         * already requires the parent to be a directory. */
        chase_flags &= ~(CHASE_MUST_BE_DIRECTORY|CHASE_MUST_BE_REGULAR|CHASE_MUST_BE_SOCKET);

        if (i && isempty(path)) {
                if (!empty_or_root(i->path))
                        return iref_parent_full(i, ret, ret_filename);

                path = ".";
        }

        /* We chase without CHASE_EXTRACT_FILENAME, because we need the full path for the returned iref. */
        IRef *root = iref_root(i);
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int parent_fd = -EBADF;
        r = chaseat(iref_fd(root), iref_fd(i), path, chase_flags|CHASE_PARENT, &p, &parent_fd);
        if (r < 0)
                return r;

        _cleanup_free_ char *dir_path = NULL, *fname = NULL;
        r = chase_split_prefix_filename(p, /* root= */ NULL, &dir_path, ret_filename ? &fname : NULL);
        if (r < 0)
                return r;

        _cleanup_free_ char *full = NULL;
        r = chaseat_make_absolute(dir_path, i && !path_is_absolute(path) ? i->path : "/", &full);
        if (r < 0)
                return r;

        r = iref_new(&parent_fd, &full, root, /* parent= */ NULL, ret);
        if (r < 0)
                return r;

        if (ret_filename)
                *ret_filename = TAKE_PTR(fname);
        return 0;
}

int iref_open(IRef *i, const char *path, IRefFlags flags, IRef **ret) {
        struct statx stx;
        ChaseFlags chase_flags;
        XOpenFlags xopen_flags;
        int open_flags, r;

        assert(path);
        assert(ret);
        assert(!(flags & IREF_UNSUPPORTED_LOOKUP_FLAGS));

        iref_flags_to_native(flags, &open_flags, &chase_flags, &xopen_flags);

        IRef *root = iref_root(i);
        if (isempty(path)) {
                _cleanup_close_ int path_fd = -EBADF;
                r = chaseat(iref_fd(root), iref_fd(i), path, chase_flags, /* ret_path= */ NULL, &path_fd);
                if (r < 0)
                        return r;

                _cleanup_close_ int fd = chase_xopenat(path_fd, /* path= */ NULL, chase_flags,
                                                     open_flags|O_NOFOLLOW, xopen_flags|XO_EMPTY_PATH);
                if (fd < 0)
                        return fd;

                _cleanup_free_ char *full = strdup(i ? i->path : "/");
                if (!full)
                        return -ENOMEM;

                return iref_new(&fd, &full, root, i ? i->parent : NULL, ret);
        }

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *filename = NULL;
        r = iref_open_parent(i, path, flags & IREF_LOOKUP_FLAGS, &parent, &filename);
        if (r < 0)
                return r;

        _cleanup_free_ char *full = path_join(parent->path, filename);
        if (!full)
                return -ENOMEM;

        path_simplify(full);

        _cleanup_close_ int fd = chase_xopenat(parent->fd, streq(filename, ".") ? NULL : filename,
                                               chase_flags, open_flags|O_NOFOLLOW, xopen_flags|XO_EMPTY_PATH);
        if (fd < 0)
                return fd;

        r = xstatx(fd, /* path= */ NULL, FLAGS_SET(chase_flags, CHASE_NO_SYNC) ? AT_STATX_DONT_SYNC : 0,
                   STATX_TYPE, &stx);
        if (r < 0)
                return r;

        return iref_new(&fd, &full, root, S_ISDIR(stx.stx_mode) ? NULL : parent, ret);
}

int iref_fopen_unlocked(IRef *i, const char *path, IRefFlags flags, const char *mode, FILE **ret) {
        ChaseFlags chase_flags;

        assert(path);
        assert(mode);
        assert(ret);
        assert(!(flags & ~IREF_LOOKUP_FLAGS));
        assert(!(flags & IREF_UNSUPPORTED_LOOKUP_FLAGS));

        iref_flags_to_native(flags, /* ret_open_flags= */ NULL, &chase_flags, /* ret_xopen_flags= */ NULL);

        return chase_and_fopenat_unlocked(iref_fd(iref_root(i)), iref_fd(i), path, chase_flags, mode, /* ret_path= */ NULL, ret);
}

int iref_parent(IRef *i, IRef **ret) {
        int r;

        assert(i);
        assert(ret);

        if (i->parent) {
                *ret = iref_ref(i->parent);
                return 0;
        }

        /* iref_open() can create another reference to the root inode. The root guard must compare inode
         * and mount identity. */
        IRef *root = iref_root(i);
        r = root ? fds_inode_and_mount_same(i->fd, root->fd) : dir_fd_is_root(i->fd);
        if (r < 0)
                return r;
        if (r > 0)
                return -EINVAL;

        return iref_open(i, "..", IREF_PATH, ret);
}

int iref_parent_full(IRef *i, IRef **ret, char **ret_filename) {
        int r;

        assert(i);
        assert(ret);

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        r = iref_parent(i, &parent);
        if (r < 0)
                return r;

        _cleanup_free_ char *filename = NULL;
        if (ret_filename) {
                r = path_extract_filename(i->path, &filename);
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

int iref_stat(const IRef *i, struct stat *ret) {
        assert(i);
        assert(ret);

        return RET_NERRNO(fstat(i->fd, ret));
}

int iref_readlink(const IRef *i, char **ret) {
        assert(i);
        assert(ret);

        return readlinkat_malloc(i->fd, "", ret);
}

int iref_access(const IRef *i, const char *filename, int type) {
        assert(i);
        assert(iref_filename_is_valid(filename));

        return RET_NERRNO(faccessat(i->fd, filename, type, AT_SYMLINK_NOFOLLOW));
}

int iref_mkdir(const IRef *i, const char *filename, mode_t mode) {
        assert(i);
        assert(iref_filename_is_valid(filename));

        return RET_NERRNO(mkdirat(i->fd, filename, mode));
}

int iref_unlink(IRef *i, const char *filename, int flags) {
        int r;

        assert(i);
        assert(isempty(filename) || iref_filename_is_valid(filename));

        if (!isempty(filename))
                return RET_NERRNO(unlinkat(i->fd, filename, flags));

        _cleanup_(iref_unrefp) IRef *parent = NULL;
        _cleanup_free_ char *basename = NULL;
        r = iref_verify_entry(i, &parent, &basename);
        if (r < 0)
                return r;

        return RET_NERRNO(unlinkat(parent->fd, basename, flags));
}

int iref_rename(IRef *from, const char *from_name, IRef *to, const char *to_name, unsigned flags) {
        int r;

        assert(from);
        assert(isempty(from_name) || iref_filename_is_valid(from_name));
        assert(to);
        assert(iref_filename_is_valid(to_name));

        if (!isempty(from_name))
                return RET_NERRNO(renameat2(from->fd, from_name, to->fd, to_name, flags));

        _cleanup_(iref_unrefp) IRef *from_parent = NULL;
        _cleanup_free_ char *from_basename = NULL;
        r = iref_verify_entry(from, &from_parent, &from_basename);
        if (r < 0)
                return r;

        _cleanup_free_ char *new_path = path_join(to->path, to_name);
        if (!new_path)
                return -ENOMEM;

        if (renameat2(from_parent->fd, from_basename, to->fd, to_name, flags) < 0)
                return -errno;

        free_and_replace(from->path, new_path);

        if (from->parent)
                unref_and_replace_new_ref(from->parent, to, iref_ref, iref_unref);

        /* iref_verify_entry() refuses the root directory, so from isn't a root iref and from->root is its
         * root. */
        unref_and_replace_new_ref(from->root, iref_root(to), iref_ref, iref_unref);

        return 0;
}
