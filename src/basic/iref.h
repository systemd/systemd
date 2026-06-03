/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "basic-forward.h"
#include "chase.h"
#include "fs-util.h"

/* A reference to an inode in the filesystem, combining a path, an fd (opened O_PATH by default), and an
 * optional reference to a root inode ref that acts as the directory under which paths are resolved.
 *
 * Multi-component path resolution goes through iref_open_parent_full(), which calls chaseat() with the
 * root iref's fd as root_fd and i's fd as dir_fd (or i->parent's fd when i is a symlink). iref_open_full()
 * builds on top of it to resolve and open the final component. Self-operations (stat/readlink) work
 * directly on the fd. Directory operations (unlink/mkdir/rename) take a single filename component and
 * operate on i->fd with *at() syscalls. When a custom root is set, O_NOFOLLOW is added to final opens to
 * prevent symlink escapes.
 *
 * InodeRefs are always heap-allocated and reference counted via iref_ref()/iref_unref().
 * Clean up with _cleanup_(iref_unrefp). */

DECLARE_TRIVIAL_REF_UNREF_FUNC(InodeRef, iref);
DEFINE_TRIVIAL_CLEANUP_FUNC(InodeRef*, iref_unref);

bool iref_is_set(const InodeRef *i);
int iref_is_root(const InodeRef *i);
/* Mark this iref as a root boundary. Children resolved through it (via iref_open_full/iref_open_parent_full)
 * will use this iref as their root. The self-reference is weak (not refcounted); children hold strong refs
 * back to it. After this call iref_path() returns "/" for i, and i's stored path is exposed as the host
 * path via iref_root_path() on its descendants. Must be called on an iref that does not already have a
 * root — nested root boundaries are not supported. */
void iref_make_root(InodeRef *i);

int iref_fd(const InodeRef *i);
/* Returns the path of this iref relative to its root. "/" for root irefs themselves. */
const char* iref_path(const InodeRef *i);
/* Returns the host path of the root boundary of this iref. "/" when no custom root is set. */
const char* iref_root_path(const InodeRef *i);

/* Install a callback invoked just before this iref's fd/path are released (i.e. when its refcount reaches
 * zero). Typical use: resource cleanup tied to the iref's lifetime (e.g. rm_rf'ing a temporary directory). */
void iref_set_destroy_callback(InodeRef *i, void (*destroy_callback)(InodeRef *i));

/* Resolve a (potentially multi-component) path relative to i and return an InodeRef pinning the resolved
 * parent directory plus the final path component in ret_filename (may be NULL to discard). chaseat() is
 * called with i->root->fd as root_fd and i->fd as dir_fd (or i->parent->fd when i is a symlink); when i
 * is NULL, resolution is against the host root.
 *
 * open_flags/xopen_flags/mode are applied to the parent fd via xopenat_full(); when open_flags and
 * xopen_flags are 0 and mode is MODE_INVALID the O_PATH fd returned by chaseat() is kept as-is. */
int iref_open_parent_full(
                const InodeRef *i,
                const char *path,
                int open_flags,
                XOpenFlags xopen_flags,
                ChaseFlags chase_flags,
                mode_t mode,
                InodeRef **ret,
                char **ret_filename);
static inline int iref_open_parent(
                const InodeRef *i,
                const char *path,
                ChaseFlags chase_flags,
                InodeRef **ret,
                char **ret_filename) {
        return iref_open_parent_full(i, path, O_DIRECTORY|O_CLOEXEC, 0, chase_flags, MODE_INVALID, ret, ret_filename);
}

/* Resolve a path relative to i and open the final component. The parent is resolved with
 * iref_open_parent_full() (honoring chase_flags), then xopenat_full() opens the final component with
 * open_flags/xopen_flags/mode. The returned iref's .parent is the resolved parent dir, enabling later
 * symlink resolution. Automatically adds O_NOFOLLOW to the final open when a custom root is set. */
int iref_open_full(
                const InodeRef *i,
                const char *path,
                int open_flags,
                XOpenFlags xopen_flags,
                ChaseFlags chase_flags,
                mode_t mode,
                InodeRef **ret);
static inline int iref_open(const InodeRef *i, const char *path, int open_flags, mode_t mode, InodeRef **ret) {
        return iref_open_full(i, path, open_flags, 0, 0, mode, ret);
}

/* Return the parent directory iref. For non-directory irefs the parent is pinned at creation (needed
 * for symlink chase). For directory irefs it is computed on demand via openat(fd, "..") and cached in
 * i for subsequent calls. Returns -EINVAL if i is the root boundary. */
int iref_parent(const InodeRef *i, InodeRef **ret);

int iref_fopen(const InodeRef *i, const char *filename, const char *mode, FILE **ret);
int iref_access(const InodeRef *i, const char *filename, int type);
int iref_stat(const InodeRef *i, struct stat *ret);
int iref_readlink(const InodeRef *i, char **ret);
/* Unlink filename under i. If filename is NULL or empty, unlink the i iref itself; in that case i must
 * not be a root iref. */
int iref_unlink(const InodeRef *i, const char *filename, int flags);
int iref_mkdir(const InodeRef *i, const char *filename, mode_t mode);
/* Rename from_name (a filename, not a path) under from, to to_name under to. If from_name is NULL
 * or empty, rename the from iref itself; in that case from must not be a root iref. */
int iref_rename(const InodeRef *from, const char *from_name, const InodeRef *to, const char *to_name, unsigned flags);
