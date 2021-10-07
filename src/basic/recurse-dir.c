/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "dirent-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "mountpoint-util.h"
#include "recurse-dir.h"
#include "sort-util.h"

#define DEFAULT_RECURSION_MAX 100

static int sort_func(struct dirent * const *a, struct dirent * const *b) {
        return strcmp((*a)->d_name, (*b)->d_name);
}

struct dirent** readdir_all_free(struct dirent **array) {

        /* Destructor that relies on the fact that the array of dirent structure pointers is NULL
         * terminated */

        if (!array)
                return NULL;

        for (struct dirent **i = array; *i; i++)
                free(*i);

        return mfree(array);
}

int readdir_all(DIR *d,
                RecurseDirFlags flags,
                struct dirent ***ret) {

        _cleanup_(readdir_all_freep) struct dirent **de_array = NULL;
        size_t n_de = 0;

        assert(d);

        /* Returns an array with pointers to "struct dirent" directory entries, optionally sorted. Free the
         * array with readdir_all_freep(). */

        for (;;) {
                _cleanup_free_ struct dirent *copy = NULL;
                struct dirent *de;

                errno = 0;
                de = readdir(d);
                if (!de) {
                        if (errno == 0)
                                break;

                        return -errno;
                }

                /* Depending on flag either ignore everything starting with ".", or just "." itself and ".." */
                if (FLAGS_SET(flags, RECURSE_DIR_IGNORE_DOT) ?
                    de->d_name[0] == '.' :
                    dot_or_dot_dot(de->d_name))
                        continue;

                if (n_de >= INT_MAX) /* Make sure we can return the number as 'int' return value */
                        return -ERANGE;

                if (!GREEDY_REALLOC(de_array, n_de+2))
                        return -ENOMEM;

                copy = memdup(de, de->d_reclen);
                if (!copy)
                        return -ENOMEM;

                de_array[n_de++] = TAKE_PTR(copy);
                de_array[n_de] = NULL; /* guarantee array remains NUL terminated */
        }

        if (FLAGS_SET(flags, RECURSE_DIR_SORT))
                typesafe_qsort(de_array, n_de, sort_func);

        if (ret)
                *ret = TAKE_PTR(de_array);

        return (int) n_de;
}

int recurse_dir(
                DIR *d,
                const char *path,
                unsigned statx_mask,
                unsigned n_depth_max,
                RecurseDirFlags flags,
                recurse_dir_func_t func,
                void *userdata) {

        _cleanup_(readdir_all_freep) struct dirent **de = NULL;
        int r, n;

        assert(d);
        assert(func);

        /* This is a lot like ftw()/nftw(), but a lot more modern, i.e. built around openat()/statx(), and
         * under the assumption that fds are not as 'expensive' as they used to be. */

        if (n_depth_max == 0)
                return -EOVERFLOW;
        if (n_depth_max == UINT_MAX) /* special marker for "default" */
                n_depth_max = DEFAULT_RECURSION_MAX;

        n = readdir_all(d, flags, &de);
        if (n < 0)
                return n;

        for (int i = 0; i < n; i++) {
                _cleanup_free_ char *joined = NULL;
                _cleanup_closedir_ DIR *subdir = NULL;
                _cleanup_close_ int inode_fd = -1;
                STRUCT_STATX_DEFINE(sx);
                bool sx_valid = false;
                const char *p;

                /* For each directory entry we'll do one of the following:
                 *
                 * 1) If the entry refers to a directory, we'll open it as O_DIRECTORY 'subdir' and then statx() the opened directory if requested
                 * 2) Otherwise and RECURSE_DIR_INODE_FD is set we'll open O_PATH 'inode_fd' and then statx() the opened inode
                 * 3) Otherwise we'll statx() the directory entry via the directory we are currently looking at
                 */

                if (path) {
                        joined = path_join(path, de[i]->d_name);
                        if (!joined)
                                return -ENOMEM;

                        p = joined;
                } else
                        p = de[i]->d_name;

                if (IN_SET(de[i]->d_type, DT_UNKNOWN, DT_DIR)) {
                        subdir = xopendirat(dirfd(d), de[i]->d_name, O_NOFOLLOW);
                        if (!subdir) {
                                if (errno == ENOENT) /* Vanished by now, go for next file immediately */
                                        continue;

                                /* If it is a subdir but we failed to open it, then fail */
                                if (!IN_SET(errno, ENOTDIR, ELOOP)) {
                                        log_debug_errno(errno, "Failed to open directory '%s': %m", p);

                                        assert(errno <= RECURSE_DIR_SKIP_OPEN_DIR_ERROR_MAX - RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE);

                                        r = func(RECURSE_DIR_SKIP_OPEN_DIR_ERROR_BASE + errno,
                                                 p,
                                                 dirfd(d),
                                                 -1,
                                                 de[i],
                                                 NULL,
                                                 userdata);
                                        if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                                break;
                                        if (!IN_SET(r, RECURSE_DIR_CONTINUE, RECURSE_DIR_SKIP_ENTRY))
                                                return r;

                                        continue;
                                }

                                /* If it's not a subdir, then let's handle it like a regular inode below */

                        } else {
                                /* If we managed to get a DIR* off the inode, it's definitely a directory. */
                                de[i]->d_type = DT_DIR;

                                if (statx_mask != 0 || (flags & RECURSE_DIR_SAME_MOUNT)) {
                                        r = statx_fallback(dirfd(subdir), "", AT_EMPTY_PATH, statx_mask, &sx);
                                        if (r < 0)
                                                return r;

                                        sx_valid = true;
                                }
                        }
                }

                if (!subdir) {
                        /* It's not a subdirectory. */

                        if (flags & RECURSE_DIR_INODE_FD) {

                                inode_fd = openat(dirfd(d), de[i]->d_name, O_PATH|O_NOFOLLOW|O_CLOEXEC);
                                if (inode_fd < 0) {
                                        if (errno == ENOENT) /* Vanished by now, go for next file immediately */
                                                continue;

                                        log_debug_errno(errno, "Failed to open directory entry '%s': %m", p);

                                        assert(errno <= RECURSE_DIR_SKIP_OPEN_INODE_ERROR_MAX - RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE);

                                        r = func(RECURSE_DIR_SKIP_OPEN_INODE_ERROR_BASE + errno,
                                                 p,
                                                 dirfd(d),
                                                 -1,
                                                 de[i],
                                                 NULL,
                                                 userdata);
                                        if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                                break;
                                        if (!IN_SET(r, RECURSE_DIR_CONTINUE, RECURSE_DIR_SKIP_ENTRY))
                                                return r;

                                        continue;
                                }

                                /* If we open the inode, then verify it's actually a non-directory, like we
                                 * assume. Let's guarantee that we never pass statx data of a directory where
                                 * caller expects a non-directory */

                                r = statx_fallback(inode_fd, "", AT_EMPTY_PATH, statx_mask | STATX_TYPE, &sx);
                                if (r < 0)
                                        return r;

                                assert(sx.stx_mask & STATX_TYPE);
                                sx_valid = true;

                                if (S_ISDIR(sx.stx_mode)) {
                                        /* What? It's a directory now? Then someone must have quickly
                                         * replaced it. Let's handle that gracefully: convert it to a
                                         * directory fd — which sould be riskless now that we pinned the
                                         * inode. */

                                        subdir = xopendirat(AT_FDCWD, FORMAT_PROC_FD_PATH(inode_fd), 0);
                                        if (!subdir)
                                                return -errno;

                                        inode_fd = safe_close(inode_fd);
                                }

                        } else if (statx_mask != 0 || (de[i]->d_type == DT_UNKNOWN && (flags & RECURSE_DIR_ENSURE_TYPE))) {

                                r = statx_fallback(dirfd(d), de[i]->d_name, AT_SYMLINK_NOFOLLOW, statx_mask | STATX_TYPE, &sx);
                                if (r == -ENOENT) /* Vanished by now? Go for next file immediately */
                                        continue;
                                if (r < 0) {
                                        log_debug_errno(r, "Failed to stat directory entry '%s': %m", p);

                                        assert(errno <= RECURSE_DIR_SKIP_STAT_INODE_ERROR_MAX - RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE);

                                        r = func(RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE + -r,
                                                 p,
                                                 dirfd(d),
                                                 -1,
                                                 de[i],
                                                 NULL,
                                                 userdata);
                                        if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                                break;
                                        if (!IN_SET(r, RECURSE_DIR_CONTINUE, RECURSE_DIR_SKIP_ENTRY))
                                                return r;

                                        continue;
                                }

                                assert(sx.stx_mask & STATX_TYPE);
                                sx_valid = true;

                                if (S_ISDIR(sx.stx_mode)) {
                                        /* So it suddenly is a directory, but we couldn't open it as such
                                         * earlier?  That is weird, and probably means somebody is racing
                                         * against us. We could of course retry and open it as a directory
                                         * again, but the chance to win here is limited. Hence, let's
                                         * propagate this as EISDIR error instead. That way we make this
                                         * something that can be reasonably handled, even though we give the
                                         * guarantee that RECURSE_DIR_ENTRY is strictly issued for
                                         * non-directory dirents. */

                                        log_debug_errno(r, "Non-directory entry '%s' suddenly became a directory: %m", p);

                                        r = func(RECURSE_DIR_SKIP_STAT_INODE_ERROR_BASE + EISDIR,
                                                 p,
                                                 dirfd(d),
                                                 -1,
                                                 de[i],
                                                 NULL,
                                                 userdata);
                                        if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                                break;
                                        if (!IN_SET(r, RECURSE_DIR_CONTINUE, RECURSE_DIR_SKIP_ENTRY))
                                                return r;

                                        continue;
                                }
                        }
                }

                if (sx_valid) {
                        /* Copy over the data we acquired through statx() if we acquired any */
                        if (sx.stx_mask & STATX_TYPE) {
                                assert(!!subdir == !!S_ISDIR(sx.stx_mode));
                                de[i]->d_type = IFTODT(sx.stx_mode);
                        }

                        if (sx.stx_mask & STATX_INO)
                                de[i]->d_ino = sx.stx_ino;
                }

                if (subdir) {
                        if (FLAGS_SET(flags, RECURSE_DIR_SAME_MOUNT)) {
                                bool is_mount;

                                if (sx_valid && FLAGS_SET(sx.stx_attributes_mask, STATX_ATTR_MOUNT_ROOT))
                                        is_mount = FLAGS_SET(sx.stx_attributes, STATX_ATTR_MOUNT_ROOT);
                                else {
                                        r = fd_is_mount_point(dirfd(d), de[i]->d_name, 0);
                                        if (r < 0)
                                                log_debug_errno(r, "Failed to determine whether %s is a submount, assuming not: %m", p);

                                        is_mount = r > 0;
                                }

                                if (is_mount) {
                                        r = func(RECURSE_DIR_SKIP_MOUNT,
                                                 p,
                                                 dirfd(d),
                                                 dirfd(subdir),
                                                 de[i],
                                                 statx_mask != 0 ? &sx : NULL, /* only pass sx if user asked for it */
                                                 userdata);
                                        if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                                break;
                                        if (!IN_SET(r, RECURSE_DIR_CONTINUE, RECURSE_DIR_SKIP_ENTRY))
                                                return r;

                                        continue;
                                }
                        }

                        if (n_depth_max <= 1) {
                                /* When we reached max depth, generate a special event */

                                r = func(RECURSE_DIR_SKIP_DEPTH,
                                         p,
                                         dirfd(d),
                                         dirfd(subdir),
                                         de[i],
                                         statx_mask != 0 ? &sx : NULL, /* only pass sx if user asked for it */
                                         userdata);
                                if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                        break;
                                if (!IN_SET(r, RECURSE_DIR_CONTINUE, RECURSE_DIR_SKIP_ENTRY))
                                        return r;

                                continue;
                        }

                        r = func(RECURSE_DIR_ENTER,
                                 p,
                                 dirfd(d),
                                 dirfd(subdir),
                                 de[i],
                                 statx_mask != 0 ? &sx : NULL, /* only pass sx if user asked for it */
                                 userdata);
                        if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                                break;
                        if (r == RECURSE_DIR_SKIP_ENTRY)
                                continue;
                        if (r != RECURSE_DIR_CONTINUE)
                                return r;

                        r = recurse_dir(subdir,
                                        p,
                                        statx_mask,
                                        n_depth_max - 1,
                                        flags,
                                        func,
                                        userdata);
                        if (r != 0)
                                return r;

                        r = func(RECURSE_DIR_LEAVE,
                                 p,
                                 dirfd(d),
                                 dirfd(subdir),
                                 de[i],
                                 statx_mask != 0 ? &sx : NULL, /* only pass sx if user asked for it */
                                 userdata);
                } else
                        /* Non-directory inode */
                        r = func(RECURSE_DIR_ENTRY,
                                 p,
                                 dirfd(d),
                                 inode_fd,
                                 de[i],
                                 statx_mask != 0 ? &sx : NULL, /* only pass sx if user asked for it */
                                 userdata);


                if (r == RECURSE_DIR_LEAVE_DIRECTORY)
                        break;
                if (!IN_SET(r, RECURSE_DIR_SKIP_ENTRY, RECURSE_DIR_CONTINUE))
                        return r;
        }

        return 0;
}

int recurse_dir_at(
                int atfd,
                const char *path,
                unsigned statx_mask,
                unsigned n_depth_max,
                RecurseDirFlags flags,
                recurse_dir_func_t func,
                void *userdata) {

        _cleanup_closedir_ DIR *d = NULL;

        d = xopendirat(atfd, path, 0);
        if (!d)
                return -errno;

        return recurse_dir(d, path, statx_mask, n_depth_max, flags, func, userdata);
}
