/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "chase.h"
#include "cleanup-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "iref.h"
#include "path-util.h"
#include "string-util.h"

struct InodeRef {
        unsigned n_ref;
        char *path;              /* owned mutable path; NULL means "/".
                                  * For non-root irefs: relative to root (exposed via iref_path()).
                                  * For root irefs (root == self): the host path of this boundary
                                  * (exposed via iref_root_path() from its descendants; iref_path()
                                  * returns "/" since root is relative to itself). */
        int fd;                  /* O_PATH|O_CLOEXEC by default; -EBADF when unset */
        InodeRef *root;          /* shared via refcount; NULL means the host root "/".
                                  * when root == self, this iref IS the root boundary (weak/unowned ref);
                                  * children created from it hold strong refs back to it */
        InodeRef *parent;        /* parent directory; shared via refcount.
                                  * used as dir_fd when chasing from a symlink iref (since the
                                  * symlink fd itself can't be used as a dir_fd). */
        void (*destroy_callback)(InodeRef *i); /* optional, invoked before fd/path are released on free */
};

static InodeRef* iref_free(InodeRef *i) {
        if (!i)
                return NULL;

        if (i->destroy_callback)
                i->destroy_callback(i);

        safe_close(i->fd);
        free(i->path);

        /* Self-referential root is a weak ref — don't unref ourselves */
        if (i->root != i)
                iref_unref(i->root);
        iref_unref(i->parent);

        return mfree(i);
}

DEFINE_TRIVIAL_REF_UNREF_FUNC(InodeRef, iref, iref_free);

bool iref_is_set(const InodeRef *i) {
        if (!i)
                return false;

        return i->fd >= 0;
}

int iref_is_root(const InodeRef *i) {
        assert(i);

        return dir_fd_is_root(i->fd);
}

void iref_make_root(InodeRef *i) {
        assert(i);
        assert(!i->root);

        i->root = i;
}

int iref_fd(const InodeRef *i) {
        assert(i);
        return i->fd;
}

void iref_set_destroy_callback(InodeRef *i, void (*destroy_callback)(InodeRef *i)) {
        assert(i);

        i->destroy_callback = destroy_callback;
}

const char* iref_path(const InodeRef *i) {
        assert(i);

        if (i->root == i)
                return "/";

        return i->path ?: "/";
}

const char* iref_root_path(const InodeRef *i) {
        assert(i);

        if (!i->root)
                return "/";

        return i->root->path ?: "/";
}

/* Returns the root_fd (chroot boundary) for chase operations on i. This is i->root->fd when a root is set,
 * or XAT_FDROOT (meaning the host root) otherwise. */
static int iref_root_fd(const InodeRef *i) {
        return i && i->root ? i->root->fd : XAT_FDROOT;
}

int iref_open_parent_full(
                const InodeRef *i,
                const char *path,
                int open_flags,
                XOpenFlags xopen_flags,
                ChaseFlags chase_flags,
                mode_t mode,
                InodeRef **ret,
                char **ret_filename) {

        int r;

        assert(path);
        assert(ret);

        /* If i is a symlink, we can't use its fd as dir_fd. Instead, read the link target,
         * join it with the caller's path, and chase from the parent directory. */
        _cleanup_free_ char *link_path = NULL;
        int dir_fd;
        if (i) {
                struct stat st;
                if (fstat(i->fd, &st) < 0)
                        return -errno;

                if (S_ISLNK(st.st_mode)) {
                        _cleanup_free_ char *link_target = NULL;
                        r = readlinkat_malloc(i->fd, "", &link_target);
                        if (r < 0)
                                return r;
                        if (!i->parent)
                                return -ENOTDIR;
                        if (isempty(path))
                                link_path = TAKE_PTR(link_target);
                        else {
                                link_path = path_join(link_target, path);
                                if (!link_path)
                                        return -ENOMEM;
                        }
                        dir_fd = i->parent->fd;
                        path = link_path;
                } else
                        dir_fd = i->fd;
        } else
                dir_fd = XAT_FDROOT;

        /* Chase without CHASE_EXTRACT_FILENAME so we retain the full parent path for the returned
         * iref, then split out the final component manually. */
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int parent_fd = -EBADF;
        r = chaseat(iref_root_fd(i), dir_fd, path,
                    (chase_flags|CHASE_PARENT) & ~CHASE_EXTRACT_FILENAME, &p, &parent_fd);
        if (r < 0)
                return r;

        _cleanup_free_ char *dir = NULL, *fname = NULL;
        r = path_split_prefix_filename(p, &dir, &fname);
        if (r < 0 && r != -EADDRNOTAVAIL)
                return r;

        if (open_flags != 0 || xopen_flags != 0 || mode != MODE_INVALID) {
                _cleanup_close_ int reopened = xopenat_full(parent_fd, ".", open_flags, xopen_flags, mode);
                if (reopened < 0)
                        return reopened;
                close_and_replace(parent_fd, reopened);
        }

        _cleanup_(iref_unrefp) InodeRef *j = new(InodeRef, 1);
        if (!j)
                return -ENOMEM;

        *j = (InodeRef) {
                .n_ref = 1,
                .fd = TAKE_FD(parent_fd),
                .path = dir ? TAKE_PTR(dir) : TAKE_PTR(p),
                .root = i ? iref_ref(i->root) : NULL,
        };

        if (ret_filename) {
                if (fname)
                        *ret_filename = TAKE_PTR(fname);
                else {
                        r = strdup_to(ret_filename, ".");
                        if (r < 0)
                                return r;
                }
        }

        *ret = TAKE_PTR(j);

        return 0;
}

int iref_open_full(
                const InodeRef *i,
                const char *path,
                int open_flags,
                XOpenFlags xopen_flags,
                ChaseFlags chase_flags,
                mode_t mode,
                InodeRef **ret) {

        int r;

        assert(path);
        assert(ret);

        _cleanup_(iref_unrefp) InodeRef *parent = NULL;
        _cleanup_free_ char *fname = NULL;
        r = iref_open_parent_full(i, path, 0, 0, chase_flags, MODE_INVALID, &parent, &fname);
        if (r < 0)
                return r;

        if (parent->root)
                open_flags |= O_NOFOLLOW;

        _cleanup_close_ int opened_fd = xopenat_full(parent->fd, fname, open_flags, xopen_flags, mode);
        if (opened_fd < 0)
                return opened_fd;

        struct stat st;
        if (fstat(opened_fd, &st) < 0)
                return -errno;

        _cleanup_free_ char *joined = path_join(iref_path(parent), fname);
        if (!joined)
                return -ENOMEM;

        _cleanup_(iref_unrefp) InodeRef *j = new(InodeRef, 1);
        if (!j)
                return -ENOMEM;

        *j = (InodeRef) {
                .n_ref = 1,
                .fd = TAKE_FD(opened_fd),
                .path = TAKE_PTR(joined),
                .root = iref_ref(parent->root),
                /* For directories the parent can be reconstructed on demand via openat(".."), so don't
                 * pin it eagerly. Non-directories need it retained (e.g. symlink chase fallback). */
                .parent = S_ISDIR(st.st_mode) ? NULL : TAKE_PTR(parent),
        };

        *ret = TAKE_PTR(j);
        return 0;
}

int iref_parent(const InodeRef *i, InodeRef **ret) {
        int r;

        assert(i);
        assert(ret);

        if (i->parent) {
                *ret = iref_ref(i->parent);
                return 0;
        }

        if (i->root == i)
                return -EINVAL;

        _cleanup_close_ int parent_fd = openat(i->fd, "..", O_PATH|O_CLOEXEC|O_DIRECTORY);
        if (parent_fd < 0)
                return -errno;

        _cleanup_free_ char *parent_path = NULL;
        if (i->path) {
                r = path_extract_directory(i->path, &parent_path);
                if (r < 0 && !IN_SET(r, -EDESTADDRREQ, -EADDRNOTAVAIL))
                        return r;
        }

        _cleanup_(iref_unrefp) InodeRef *p = new(InodeRef, 1);
        if (!p)
                return -ENOMEM;

        *p = (InodeRef) {
                .n_ref = 1,
                .fd = TAKE_FD(parent_fd),
                .path = TAKE_PTR(parent_path),
                .root = i->root ? iref_ref(i->root) : NULL,
        };

        *ret = TAKE_PTR(p);
        return 0;
}

int iref_fopen(const InodeRef *i, const char *filename, const char *mode, FILE **ret) {
        assert(i);
        assert(filename_is_valid(filename));
        assert(ret);

        return xfopenat(i->fd, filename, mode, i->root ? O_NOFOLLOW : 0, ret);
}

int iref_access(const InodeRef *i, const char *filename, int type) {
        assert(i);
        assert(filename_is_valid(filename));

        return RET_NERRNO(faccessat(i->fd, filename, type, AT_SYMLINK_NOFOLLOW));
}

int iref_stat(const InodeRef *i, struct stat *ret) {
        assert(i);
        assert(ret);

        return RET_NERRNO(fstat(i->fd, ret));
}

int iref_readlink(const InodeRef *i, char **ret) {
        assert(i);
        assert(ret);

        return readlinkat_malloc(i->fd, "", ret);
}

int iref_unlink(const InodeRef *i, const char *filename, int flags) {
        int r;

        assert(i);
        assert(isempty(filename) || filename_is_valid(filename));

        int dir_fd = i->fd;
        _cleanup_free_ char *basename = NULL;
        _cleanup_(iref_unrefp) InodeRef *parent = NULL;
        if (isempty(filename)) {
                r = iref_parent(i, &parent);
                if (r < 0)
                        return r;

                r = path_extract_filename(i->path, &basename);
                if (r < 0)
                        return r;

                dir_fd = parent->fd;
                filename = basename;
        }

        return RET_NERRNO(unlinkat(dir_fd, filename, flags));
}

int iref_mkdir(const InodeRef *i, const char *filename, mode_t mode) {
        assert(i);
        assert(filename_is_valid(filename));

        return RET_NERRNO(mkdirat(i->fd, filename, mode));
}

int iref_rename(const InodeRef *from, const char *from_name, const InodeRef *to, const char *to_name, unsigned flags) {
        int r;

        assert(from);
        assert(isempty(from_name) || filename_is_valid(from_name));
        assert(to);
        assert(filename_is_valid(to_name));

        int from_fd = from->fd;
        _cleanup_free_ char *from_basename = NULL;
        _cleanup_(iref_unrefp) InodeRef *from_parent = NULL;
        if (isempty(from_name)) {
                r = iref_parent(from, &from_parent);
                if (r < 0)
                        return r;

                r = path_extract_filename(from->path, &from_basename);
                if (r < 0)
                        return r;

                from_fd = from_parent->fd;
                from_name = from_basename;
        }

        return RET_NERRNO(renameat2(from_fd, from_name, to->fd, to_name, flags));
}
