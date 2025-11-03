/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "log.h"
#include "tar-util.h"

#if HAVE_LIBARCHIVE
#include <sys/sysmacros.h>

#include "alloc-util.h"
#include "chase.h"
#include "fd-util.h"
#include "fs-util.h"
#include "iovec-util.h"
#include "libarchive-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "stat-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "xattr-util.h"

#define DEPTH_MAX 128U

typedef struct XAttr {
        char *name;
        struct iovec data;
} XAttr;

typedef struct OpenInode {
        int fd;
        char *path;

        /* File properties to apply when we are done with the inode, i.e. right before closing it */
        mode_t filetype;
        mode_t mode;
        struct timespec mtime;
        uid_t uid;
        gid_t gid;
        XAttr *xattr;
        size_t n_xattr;
} OpenInode;

static void xattr_done(XAttr *xa) {
        assert(xa);

        free(xa->name);
        iovec_done(&xa->data);
}

static void xattr_done_many(XAttr *xa, size_t n) {
        assert(xa || n == 0);

        FOREACH_ARRAY(i, xa, n)
                xattr_done(i);

        free(xa);
}

static void open_inode_done(OpenInode *of) {
        assert(of);

        if (of->path) {
                /* Only close the stored fd if the path field is set. We'll set the path to NULL for the root
                 * inode, and we don't want the fd for that closed, as it's owned by the caller. */
                of->fd = safe_close(of->fd);
                of->path = mfree(of->path);
        }
        xattr_done_many(of->xattr, of->n_xattr);
}

static void open_inode_done_many(OpenInode *array, size_t n) {
        assert(array || n == 0);

        FOREACH_ARRAY(i, array, n)
                open_inode_done(i);

        free(array);
}

static int open_inode_finalize(OpenInode *of) {
        int r = 0;

        assert(of);

        if (of->fd >= 0)  {
                int k;

                /* We adjust the UID/GID right before the mode, since doing this might affect the mode (drops
                 * suid/sgid bits).
                 *
                 * We adjust the mode only when leaving a dir, because if we are unpriv we might lose the
                 * ability to enter it once we do this. */

                if (uid_is_valid(of->uid) || gid_is_valid(of->gid) || of->mode != MODE_INVALID) {
                        k = fchmod_and_chown_with_fallback(of->fd, /* path= */ NULL, of->mode, of->uid, of->gid);
                        if (k < 0)
                                RET_GATHER(r, log_error_errno(k, "Failed to adjust ownership/mode of '%s': %m", of->path));
                }

                /* We also adjust the mtime only after leaving a dir, since it might otherwise change again
                 * because we make modifications inside it */
                if (of->mtime.tv_nsec != UTIME_OMIT) {
                        k = futimens_opath(of->fd, (const struct timespec[2]) {
                                        { .tv_nsec = UTIME_OMIT },
                                        of->mtime,
                                });
                        if (k < 0)
                                RET_GATHER(r, log_error_errno(k, "Failed to adjust mtime of '%s': %m", of->path));
                }

                /* Setting certain xattrs might cause us to lose access to the inode, hence set this last */
                FOREACH_ARRAY(i, of->xattr, of->n_xattr) {
                        k = xsetxattr_full(
                                        of->fd,
                                        /* path= */ NULL,
                                        AT_EMPTY_PATH,
                                        i->name,
                                        i->data.iov_base,
                                        i->data.iov_len,
                                        /* xattr_flags= */ 0);
                        if (k < 0)
                                RET_GATHER(r, log_error_errno(k, "Failed to set xattr '%s' of '%s': %m", i->name, of->path));
                }
        }

        open_inode_done(of); /* free this item even on failure */
        return r;
}

static int open_inode_finalize_many(OpenInode **array, size_t *n) {
        int r = 0;
        assert(array);
        assert(n);
        assert(*array || *n == 0);

        /* Go backwards, so that we adjust innermost first */
        for (size_t i = *n; i > 0; i--)
                RET_GATHER(r, open_inode_finalize(*array + i - 1));

        *array = mfree(*array);
        *n = 0;
        return r;
}

static int archive_unpack_regular(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *filename,
                const char *path) {

        int r;

        assert(a);
        assert(entry);
        assert(parent_fd >= 0);
        assert(filename);
        assert(path);

        _cleanup_free_ char *tmp = NULL;
        _cleanup_close_ int fd = open_tmpfile_linkable_at(parent_fd, filename, O_CLOEXEC|O_WRONLY, &tmp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create regular file '%s': %m", path);

        r = sym_archive_read_data_into_fd(a, fd);
        if (r != ARCHIVE_OK) {
                r = log_error_errno(
                                SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                "Failed to unpack regular file '%s': %s", path, sym_archive_error_string(a));
                goto fail;
        }

        /* If this is a sparse file, then libarchive's archive_read_data_into_fd() won't insert the final
         * hole. We need to manually truncate. */
        off_t l = lseek(fd, 0, SEEK_CUR);
        if (l < 0) {
                r = log_error_errno(errno, "Failed to determine current file position in '%s': %m", path);
                goto fail;
        }
        if (ftruncate(fd, l) < 0) {
                r = log_error_errno(errno, "Failed to truncate regular file '%s' to %" PRIu64 ": %m", path, (uint64_t) l);
                goto fail;
        }

        r = link_tmpfile_at(fd, parent_fd, tmp, filename, LINK_TMPFILE_REPLACE);
        if (r < 0) {
                log_error_errno(r, "Failed to install regular file '%s': %m", path);
                goto fail;
        }

        return TAKE_FD(fd);

fail:
        if (tmp)
                (void) unlinkat(parent_fd, tmp, /* flags= */ 0);

        return r;
}

static int archive_unpack_directory(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *filename,
                const char *path) {

        assert(a);
        assert(entry);
        assert(parent_fd >= 0);
        assert(filename);
        assert(path);

        /* For the other inode types we operate in an atomic replace fashion, but not for the directories,
         * they are more of a "shared" concept, and we try to reuse existing inodes. Note that we create the
         * dir inode in mode 0700, so that we can fully access it (but others cannot). We'll adjust the modes
         * right before closing the inode. */
        _cleanup_close_ int fd = open_mkdir_at(parent_fd, filename, O_CLOEXEC, 0700);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create directory '%s': %m", path);

        return TAKE_FD(fd);
}

static int archive_unpack_symlink(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *filename,
                const char *path) {

        int r;

        assert(a);
        assert(entry);
        assert(parent_fd >= 0);
        assert(filename);
        assert(path);

        const char *target = sym_archive_entry_symlink(entry);
        if (!target)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to get symlink target for '%s': %m", path);

        r = symlinkat_atomic_full(target, parent_fd, filename, /* flags= */ 0);
        if (r < 0)
                return log_error_errno(r, "Failed to create symlink '%s' → '%s': %m", path, target);

        _cleanup_close_ int fd = openat(parent_fd, filename, O_CLOEXEC|O_PATH|O_NOFOLLOW);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open symlink '%s' we just created: %m", path);

        r = fd_verify_symlink(fd);
        if (r < 0)
                return log_error_errno(r, "Symlink '%s' we just created is not a symlink: %m", path);

        return TAKE_FD(fd);
}

static int archive_unpack_special_inode(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *filename,
                const char *path,
                mode_t filetype) {

        int r;

        assert(a);
        assert(entry);
        assert(parent_fd >= 0);
        assert(filename);
        assert(path);

        dev_t major = 0, minor = 0;
        if (IN_SET(filetype, S_IFCHR, S_IFBLK)) {
                major = sym_archive_entry_rdevmajor(entry);
                minor = sym_archive_entry_rdevminor(entry);
        }

        r = mknodat_atomic(parent_fd, filename, filetype | 0000, makedev(major, minor));
        if (r < 0)
                return log_error_errno(r, "Failed to create special node '%s': %m", path);

        _cleanup_close_ int fd = openat(parent_fd, filename, O_CLOEXEC|O_PATH|O_NOFOLLOW);
        if (fd < 0)
                return log_error_errno(errno, "Failed to open special node '%s' we just created: %m", path);

        struct stat st;
        if (fstat(fd, &st) < 0)
                return log_error_errno(errno, "Failed to fstat() '%s': %m", path);

        if (((st.st_mode ^ filetype) & S_IFMT) != 0)
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENODEV),
                                "Special node '%s' we just created is of a wrong type: %m", path);

        return TAKE_FD(fd);
}

static int archive_entry_pathname_safe(struct archive_entry *entry, const char **ret) {
        /* libarchive prefixes all paths with "./", let's chop that off. Note that we'll return a path of
         * NULL for the root inode here! */

        assert(entry);
        assert(ret);

        const char *p = sym_archive_entry_pathname(entry);
        if (!p)
                return -EBADMSG;

        const char *e = startswith(p, "./") ?: p;
        if (isempty(e))
                *ret = NULL;
        else if (path_is_safe(e))
                *ret = e;
        else
                return -EBADMSG;

        return 0;
}

static int archive_entry_read_stat(
                struct archive_entry *entry,
                mode_t *filetype,
                mode_t *mode,
                struct timespec *mtime,
                uid_t *uid,
                gid_t *gid,
                XAttr **xa,
                size_t *n_xa,
                TarFlags flags) {

        assert(entry);

        /* Fills in all fields that are present in the archive entry. Doesn't change the fields if the entry
         * doesn't contain the relevant data */

        if (filetype)
                *filetype = sym_archive_entry_filetype(entry);

        if (mode)
                *mode = sym_archive_entry_mode(entry);

        if (mtime && sym_archive_entry_mtime_is_set(entry))
                *mtime = (struct timespec) {
                        sym_archive_entry_mtime(entry),
                        sym_archive_entry_mtime_nsec(entry),
                };
        if (uid && sym_archive_entry_uid_is_set(entry))
                *uid = sym_archive_entry_uid(entry);
        if (gid && sym_archive_entry_gid_is_set(entry))
                *gid = sym_archive_entry_gid(entry);

        (void) sym_archive_entry_xattr_reset(entry);
        for (;;) {
                const char *name = NULL;
                struct iovec data;
                (void) sym_archive_entry_xattr_next(entry, &name, (const void**) &data.iov_base, &data.iov_len);
                if (!name)
                        break;

                if (xattr_is_acl(name))
                        continue;

                if (!FLAGS_SET(flags, TAR_SELINUX) && xattr_is_selinux(name))
                        continue;

                _cleanup_free_ char *n = strdup(name);
                if (!n)
                        return log_oom();

                _cleanup_(iovec_done) struct iovec iovec_copy = {};
                if (!iovec_memdup(&data, &iovec_copy))
                        return log_oom();

                if (!GREEDY_REALLOC(*xa, *n_xa+1))
                        return log_oom();

                (*xa)[(*n_xa)++] = (XAttr) {
                        .name = TAKE_PTR(n),
                        .data = TAKE_STRUCT(iovec_copy),
                };
        }

        return 0;
}

int tar_x(int input_fd, int tree_fd, TarFlags flags) {
        int ar, r;

        assert(input_fd >= 0);
        assert(tree_fd >= 0);

        _cleanup_(archive_read_freep) struct archive *a = NULL;
        a = sym_archive_read_new();
        if (!a)
                return log_oom();

        ar = sym_archive_read_support_format_tar(a);
        if (ar != ARCHIVE_OK)
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                "Failed to enable tar unpacking: %s", sym_archive_error_string(a));

        ar = sym_archive_read_support_format_cpio(a);
        if (ar != ARCHIVE_OK)
                return log_error_errno(
                                SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                "Failed to enable cpio unpacking: %s", sym_archive_error_string(a));

        ar = sym_archive_read_open_fd(a, input_fd, 64 * 1024);
        if (ar != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to initialize archive context: %s", sym_archive_error_string(a));


        OpenInode *open_inodes = NULL;
        if (!GREEDY_REALLOC(open_inodes, 2)) /* the minimal case is a single file in an archive, which would
                                              * mean two inodes, the root dir inode, and he regular file
                                              * inode, hence start with 2 here */
                return log_oom();

        size_t n_open_inodes = 0;
        CLEANUP_ARRAY(open_inodes, n_open_inodes, open_inode_done_many);

        /* Fill in the root inode. (Note: we leave the .path field as NULL to mark it as root inode.) */
        open_inodes[0] = (OpenInode) {
                .fd = tree_fd,
                .filetype = S_IFDIR,
                .mode = MODE_INVALID,
                .mtime = { .tv_nsec = UTIME_OMIT },
                .uid = UID_INVALID,
                .gid = GID_INVALID,
        };
        n_open_inodes = 1;

        for (;;) {
                struct archive_entry *entry = NULL;

                ar = sym_archive_read_next_header(a, &entry);
                if (ar == ARCHIVE_EOF)
                        break;
                if (ar != ARCHIVE_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse archive: %s", sym_archive_error_string(a));

                const char *p = NULL;
                r = archive_entry_pathname_safe(entry, &p);
                if (r < 0)
                        return log_error_errno(r, "Invalid path name in entry, refusing.");

                if (!p) {
                        /* This is the root inode */
                        r = archive_entry_read_stat(
                                        entry,
                                        &open_inodes[0].filetype,
                                        &open_inodes[0].mode,
                                        &open_inodes[0].mtime,
                                        &open_inodes[0].uid,
                                        &open_inodes[0].gid,
                                        &open_inodes[0].xattr,
                                        &open_inodes[0].n_xattr,
                                        flags);
                        if (r < 0)
                                return r;
                        if (open_inodes[0].filetype != S_IFDIR)
                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Archives root inode is not a directory, refusing.");

                        continue;
                }

                /* Find common prefix with path elements we were looking at so far. */
                const char *rest = p;
                size_t i;
                for (i = 1; i < n_open_inodes; i++) {
                        const char *e = path_startswith(p, open_inodes[i].path);
                        if (isempty(e))
                                break;

                        rest = e;
                }

                /* Finalize all inodes we won't need anymore now (go backwards, i.e. close inner fds first) */
                while (n_open_inodes > i) {
                        r = open_inode_finalize(open_inodes + n_open_inodes - 1);
                        if (r < 0)
                                return r;

                        n_open_inodes--;
                }

                /* And now create all remaining components */
                for (;;) {
                        const char *element;

                        r = path_find_first_component(&rest, /* accept_dot_dot= */ false, &element);
                        if (r < 0)
                                return log_error_errno(r, "Failed to extract next element from path: %m");
                        if (r == 0)
                                break;

                        /* Safety check, before we add another level to our stack */
                        if (n_open_inodes >= DEPTH_MAX)
                                return log_error_errno(
                                                SYNTHETIC_ERRNO(E2BIG),
                                                "Archive's directory tree nested too deeply, refusing to descend more than %u levels.", DEPTH_MAX);

                        _cleanup_free_ char *e = strndup(element, r);
                        if (!e)
                                return log_oom();

                        const char *parent_path = NULL;
                        int parent_fd = -EBADF;
                        assert(n_open_inodes > 0);
                        parent_fd = open_inodes[n_open_inodes-1].fd;
                        parent_path = open_inodes[n_open_inodes-1].path;

                        _cleanup_free_ char *j = parent_path ? path_join(parent_path, e) : strdup(e);
                        if (!j)
                                return log_oom();

                        if (!GREEDY_REALLOC(open_inodes, n_open_inodes+1))
                                return log_oom();

                        _cleanup_close_ int fd = -EBADF;
                        mode_t filetype = MODE_INVALID;
                        mode_t mode = MODE_INVALID;
                        uid_t uid = UID_INVALID;
                        gid_t gid = GID_INVALID;
                        struct timespec mtime = { .tv_nsec = UTIME_OMIT };
                        XAttr *xa = NULL;
                        size_t n_xa = 0;
                        CLEANUP_ARRAY(xa, n_xa, xattr_done_many);

                        if (isempty(rest)) {
                                /* This is the final node in the path, create it */

                                if (sym_archive_entry_hardlink_is_set(entry)) {
                                        /* If this is a hardlink, act on it */
                                        const char *h = sym_archive_entry_hardlink(entry);
                                        if (!h)
                                                return log_error_errno(
                                                                SYNTHETIC_ERRNO(EBADMSG),
                                                                "No hardlink target in hardlink entry, refusing.");

                                        /* libarchive prefixes all paths with "./", let's chop that off */
                                        const char *target = startswith(h, "./") ?: h;
                                        if (!path_is_safe(target))
                                                return log_error_errno(
                                                                SYNTHETIC_ERRNO(EBADMSG),
                                                                "Invalid hardlink path name '%s' in entry, refusing.", target);

                                        _cleanup_close_ int target_fd = -EBADF;
                                        r = chaseat(tree_fd, target, CHASE_PROHIBIT_SYMLINKS|CHASE_AT_RESOLVE_IN_ROOT, /* ret_path= */ NULL, &target_fd);
                                        if (r < 0)
                                                return log_error_errno(
                                                                r,
                                                                "Failed to find inode '%s' which shall be hardlinked as '%s': %m", target, j);

                                        struct stat verify_st;
                                        if (fstat(target_fd, &verify_st) < 0)
                                                return log_error_errno(errno, "Failed to stat inode '%s': %m", target);

                                        /* Refuse hardlinking directories early. */
                                        if (!inode_type_can_hardlink(verify_st.st_mode))
                                                return log_error_errno(
                                                                SYNTHETIC_ERRNO(EBADF),
                                                                "Refusing to hardlink inode '%s' of type '%s': %m", target, inode_type_to_string(verify_st.st_mode));

                                        if (linkat(target_fd, "", parent_fd, e, AT_EMPTY_PATH) < 0) {
                                                if (errno != ENOENT)
                                                        return log_error_errno(
                                                                        errno,
                                                                        "Failed to hardlink inode '%s' as '%s': %m", target, j);

                                                /* To be able to link by inode fd we might have needed
                                                 * CAP_DAC_READ_SEARCH which we lacked. Let's retry with the
                                                 * parent. Yes, glibc/kernel report this as ENOENT. Kinda
                                                 * annoying. */

                                                _cleanup_close_ int target_parent_fd = -EBADF;
                                                _cleanup_free_ char *target_filename = NULL;
                                                r = chaseat(tree_fd, target, CHASE_PROHIBIT_SYMLINKS|CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_EXTRACT_FILENAME, &target_filename, &target_parent_fd);
                                                if (r < 0)
                                                        return log_error_errno(
                                                                        r,
                                                                        "Failed to find inode '%s' which shall be hardlinked as '%s': %m", target, j);

                                                if (linkat(target_parent_fd, target_filename, parent_fd, e, /* flags= */ 0) < 0)
                                                        return log_error_errno(
                                                                        errno,
                                                                        "Failed to hardlink inode '%s' as '%s': %m", target, j);
                                        }

                                        continue;
                                }

                                r = archive_entry_read_stat(
                                                entry,
                                                &filetype,
                                                &mode,
                                                &mtime,
                                                &uid,
                                                &gid,
                                                &xa,
                                                &n_xa,
                                                flags);
                                if (r < 0)
                                        return r;

                                switch (filetype) {

                                case S_IFREG:
                                        fd = archive_unpack_regular(a, entry, parent_fd, e, j);
                                        break;

                                case S_IFDIR:
                                        fd = archive_unpack_directory(a, entry, parent_fd, e, j);
                                        break;

                                case S_IFLNK:
                                        fd = archive_unpack_symlink(a, entry, parent_fd, e, j);
                                        break;

                                case S_IFCHR:
                                case S_IFBLK:
                                case S_IFIFO:
                                case S_IFSOCK:
                                        fd = archive_unpack_special_inode(a, entry, parent_fd, e, j, filetype);
                                        break;

                                default:
                                        return log_error_errno(
                                                        SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                                        "Unexpected file type %i of '%s', refusing.", (int) filetype, j);
                                }
                                if (fd < 0)
                                        return fd;

                        } else {
                                /* This is some intermediary node in the path that we haven't opened yet. Create it with default attributes */
                                fd = open_mkdir_at(parent_fd, e, O_CLOEXEC, 0700);
                                if (fd < 0)
                                        return log_error_errno(fd, "Failed to create directory '%s': %m", j);

                                filetype = S_IFDIR;
                        }

                        /* Now store a reference to the inode we just created in our stack array. Note that
                         * we have not applied file ownership, access mode, mtime here, we'll do that only
                         * when we are finished with the inode, since we have to apply them *after* we are
                         * fully done with the inode (i.e. after creating further inodes inside of dir inodes
                         * for example), due to permission problems this might create or that the mtime
                         * changes we do might still be affected by our changes. */
                        open_inodes[n_open_inodes++] = (OpenInode) {
                                .fd = TAKE_FD(fd),
                                .path = TAKE_PTR(j),
                                .filetype = filetype,
                                .mode = mode,
                                .mtime = mtime,
                                .uid = uid,
                                .gid = gid,
                                .xattr = TAKE_PTR(xa),
                                .n_xattr = n_xa,
                        };

                        n_xa = 0;
                }
        }

        r = open_inode_finalize_many(&open_inodes, &n_open_inodes);
        if (r < 0)
                return r;

        return 0;
}

static int archive_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        struct archive *a = ASSERT_PTR(userdata);
        int r;

        assert(path);

        if (!IN_SET(event, RECURSE_DIR_ENTER, RECURSE_DIR_ENTRY))
                return RECURSE_DIR_CONTINUE;

        assert(inode_fd >= 0);
        assert(sx);

        log_debug("Archiving %s\n", path);

        _cleanup_(archive_entry_freep) struct archive_entry *entry = NULL;
        entry = sym_archive_entry_new();
        if (!entry)
                return log_oom();

        assert(FLAGS_SET(sx->stx_mask, STATX_TYPE|STATX_MODE));
        sym_archive_entry_set_pathname(entry, path);
        sym_archive_entry_set_filetype(entry, sx->stx_mode);

        if (!S_ISLNK(sx->stx_mode))
                sym_archive_entry_set_perm(entry, sx->stx_mode);

        if (FLAGS_SET(sx->stx_mask, STATX_UID))
                sym_archive_entry_set_uid(entry, sx->stx_uid);
        if (FLAGS_SET(sx->stx_mask, STATX_GID))
                sym_archive_entry_set_gid(entry, sx->stx_gid);

        if (S_ISREG(sx->stx_mode)) {
                if (!FLAGS_SET(sx->stx_mask, STATX_SIZE))
                        return log_error_errno(SYNTHETIC_ERRNO(EIO), "Unable to determine file size of '%s'.", path);

                sym_archive_entry_set_size(entry, sx->stx_size);
        }

        if (S_ISCHR(sx->stx_mode) || S_ISBLK(sx->stx_mode)) {
                sym_archive_entry_set_rdevmajor(entry, sx->stx_rdev_major);
                sym_archive_entry_set_rdevminor(entry, sx->stx_rdev_minor);
        }

        /* We care about a modicum of reproducibility here, hence we don't save atime/btime here */
        if (FLAGS_SET(sx->stx_mask, STATX_MTIME))
                sym_archive_entry_set_mtime(entry, sx->stx_mtime.tv_sec, sx->stx_mtime.tv_nsec);
        if (FLAGS_SET(sx->stx_mask, STATX_CTIME))
                sym_archive_entry_set_ctime(entry, sx->stx_ctime.tv_sec, sx->stx_ctime.tv_nsec);

        if (S_ISLNK(sx->stx_mode)) {
                _cleanup_free_ char *s = NULL;

                assert(dir_fd >= 0);
                assert(de);

                r = readlinkat_malloc(dir_fd, de->d_name, &s);
                if (r < 0)
                        return log_error_errno(r, "Failed to read symlink target of '%s': %m", path);

                sym_archive_entry_set_symlink(entry, s);
        }

        if (sym_archive_write_header(a, entry) != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to write archive entry header: %s", sym_archive_error_string(a));

        if (S_ISREG(sx->stx_mode)) {
                _cleanup_close_ int data_fd = -EBADF;

                /* Convert the O_PATH fd in a proper fd */
                data_fd = fd_reopen(inode_fd, O_RDONLY|O_CLOEXEC);
                if (data_fd < 0)
                        return log_error_errno(data_fd, "Failed to open '%s': %m", path);

                for (;;) {
                        char buffer[64*1024];
                        ssize_t l;

                        l = read(data_fd, buffer, sizeof(buffer));
                        if (l < 0)
                                return log_error_errno(errno, "Failed to read '%s': %m",  path);
                        if (l == 0)
                                break;

                        la_ssize_t k;
                        k = sym_archive_write_data(a, buffer, l);
                        if (k < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to write archive data: %s", sym_archive_error_string(a));
                }
        }

        return RECURSE_DIR_CONTINUE;
}

int tar_c(int tree_fd, int output_fd, const char *filename, TarFlags flags) {
        int r;

        assert(tree_fd >= 0);
        assert(output_fd >= 0);

        _cleanup_(archive_write_freep) struct archive *a = sym_archive_write_new();
        if (!a)
                return log_oom();

        if (filename)
                r = sym_archive_write_set_format_filter_by_ext(a, filename);
        else
                r = sym_archive_write_set_format_gnutar(a);
        if (r != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to set libarchive output format: %s", sym_archive_error_string(a));

        r = sym_archive_write_open_fd(a, output_fd);
        if (r != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to set libarchive output file: %s", sym_archive_error_string(a));

        r = recurse_dir(tree_fd,
                        ".",
                        STATX_TYPE|STATX_MODE|STATX_UID|STATX_GID|STATX_SIZE|STATX_ATIME|STATX_CTIME,
                        UINT_MAX,
                        RECURSE_DIR_SORT|RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL,
                        archive_item,
                        a);
        if (r < 0)
                return log_error_errno(r, "Failed to make archive: %m");

        r = sym_archive_write_close(a);
        if (r != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unable to finish writing archive: %s", sym_archive_error_string(a));

        return 0;
}

#else

int tar_x(int input_fd, int tree_fd, TarFlags flags) {
        assert(input_fd >= 0);
        assert(tree_fd >= 0);

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libarchive support not available.");
}

int tar_c(int tree_fd, int output_fd, const char *filename, TarFlags flags) {
        assert(tree_fd >= 0);
        assert(output_fd >= 0);

        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "libarchive support not available.");
}

#endif
