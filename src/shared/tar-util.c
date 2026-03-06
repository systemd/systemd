/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "errno-util.h"
#include "log.h"
#include "tar-util.h"

#if HAVE_LIBARCHIVE
#include <sys/mount.h>
#include <sys/sysmacros.h>

#include "acl-util.h"
#include "alloc-util.h"
#include "chase.h"
#include "chattr-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "hexdecoct.h"
#include "iovec-util.h"
#include "libarchive-util.h"
#include "mountpoint-util.h"
#include "nsresource.h"
#include "nulstr-util.h"
#include "path-util.h"
#include "recurse-dir.h"
#include "rm-rf.h"
#include "sha256.h"
#include "stat-util.h"
#include "string-util.h"
#include "tmpfile-util.h"
#include "user-util.h"
#include "xattr-util.h"

#define DEPTH_MAX 128U

/* We are a bit conservative with the flags we save/restore in tar files */
#define CHATTR_TAR_FL                                                   \
        (FS_NOATIME_FL     |                                            \
         FS_NOCOW_FL       |                                            \
         FS_PROJINHERIT_FL |                                            \
         FS_NODUMP_FL      |                                            \
         FS_SYNC_FL        |                                            \
         FS_DIRSYNC_FL)

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
        unsigned fflags;
        XAttr *xattr;
        size_t n_xattr;
        acl_t acl_access, acl_default;
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
#if HAVE_ACL
        if (of->acl_access)
                sym_acl_free(of->acl_access);
        if (of->acl_default)
                sym_acl_free(of->acl_default);
#endif
}

static void open_inode_done_many(OpenInode *array, size_t n) {
        assert(array || n == 0);

        FOREACH_ARRAY(i, array, n)
                open_inode_done(i);

        free(array);
}

static int open_inode_apply_acl(OpenInode *of) {
        int r = 0;

        assert(of);
        assert(of->fd >= 0);

        if (!inode_type_can_acl(of->filetype))
                return 0;

        if (of->acl_access) {
#if HAVE_ACL
                if (sym_acl_set_fd(of->fd, of->acl_access) < 0)
                        RET_GATHER(r, log_error_errno(errno, "Failed to adjust ACLs of '%s': %m", of->path));
#else
                log_debug("The archive entry '%s' has ACLs, but ACL support is disabled.", of->path);
#endif
        }

        if (of->filetype == S_IFDIR && of->acl_default) {
#if HAVE_ACL
                /* There's no API to set default ACLs by fd, hence go by /proc/self/fd/ path */
                if (sym_acl_set_file(FORMAT_PROC_FD_PATH(of->fd), ACL_TYPE_DEFAULT, of->acl_default) < 0)
                        RET_GATHER(r, log_error_errno(errno, "Failed to adjust default ACLs of '%s': %m", of->path));
#else
                log_debug("The archive entry '%s' has default ACLs, but ACL support is disabled.", of->path);
#endif
        }

        return r;
}

static int open_inode_finalize(OpenInode *of) {
        int r = 0;

        assert(of);

        if (of->fd >= 0)  {
                int k;

                /* We adjust the UID/GID right before the mode, since doing this might affect the mode (drops
                 * suid/sgid bits).
                 *
                 * We adjust the mode only when leaving a dir, because if we are unprivileged we might lose
                 * the ability to enter it once we do this. */

                if (uid_is_valid(of->uid) || gid_is_valid(of->gid) || of->mode != MODE_INVALID) {
                        k = fchmod_and_chown_with_fallback(of->fd, /* path= */ NULL, of->mode, of->uid, of->gid);
                        if (k < 0)
                                RET_GATHER(r, log_error_errno(k, "Failed to adjust ownership/mode of '%s': %m", of->path));
                }

                k = open_inode_apply_acl(of);
                if (k < 0)
                        RET_GATHER(r, log_error_errno(k, "Failed to adjust ACL of '%s': %m", of->path));

                if ((of->fflags & ~CHATTR_EARLY_FL) != 0 && inode_type_can_chattr(of->filetype)) {
                        k = chattr_full(of->fd,
                                        /* path= */ NULL,
                                        /* value= */ of->fflags,
                                        /* mask= */ of->fflags & ~CHATTR_EARLY_FL,
                                        /* ret_previous= */ NULL,
                                        /* ret_final= */ NULL,
                                        CHATTR_FALLBACK_BITWISE);
                        if (ERRNO_IS_NEG_NOT_SUPPORTED(k))
                                log_warning_errno(k, "Failed to apply chattr of '%s', ignoring: %m", of->path);
                        else if (k < 0)
                                RET_GATHER(r, log_error_errno(k, "Failed to adjust chattr of '%s': %m", of->path));
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
                const char *path,
                unsigned fflags) {

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

        CLEANUP_TMPFILE_AT(parent_fd, tmp);

        if ((fflags & CHATTR_EARLY_FL) != 0) {
                r = chattr_full(fd,
                                /* path= */ NULL,
                                /* value= */ fflags,
                                /* mask= */ fflags & CHATTR_EARLY_FL,
                                /* ret_previous= */ NULL,
                                /* ret_final= */ NULL,
                                CHATTR_FALLBACK_BITWISE);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning_errno(r, "Failed to apply chattr of '%s', ignoring: %m", path);
                else if (r < 0)
                        return log_error_errno(r, "Failed to adjust chattr of '%s': %m", path);
        }

        r = sym_archive_read_data_into_fd(a, fd);
        if (r != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Failed to unpack regular file '%s': %s", path, sym_archive_error_string(a));

        /* If this is a sparse file, then libarchive's archive_read_data_into_fd() won't insert the final
         * hole. We need to manually truncate. */
        off_t l = lseek(fd, 0, SEEK_CUR);
        if (l < 0)
                return log_error_errno(errno, "Failed to determine current file position in '%s': %m", path);
        if (ftruncate(fd, l) < 0)
                return log_error_errno(errno, "Failed to truncate regular file '%s' to %" PRIu64 ": %m", path, (uint64_t) l);

        r = link_tmpfile_at(fd, parent_fd, tmp, filename, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to install regular file '%s': %m", path);

        tmp = mfree(tmp); /* disarm CLEANUP_TMPFILE_AT() */
        return TAKE_FD(fd);
}

static int overlayfs_fsetfattr(
                const char *path,  /* purely decorative, for log purposes */
                int fd,
                const char *name,  /* xattr key name */
                const char *value  /* xattr value */) {
        int r;

        assert(fd >= 0);
        assert(path);
        assert(name);
        assert(value);

        /* overlayfs knows magic {user|trusted}.overlay.* xattrs for whiteouts and opaque directories. The
         * 'user.overlay.*' ones are only checked if overlayfs is mounted with "userxattr". We only set that
         * one because we want to operate unprivileged. Ideally, we'd set both here, to maximize the chance
         * that things work both in privileged and unprivileged scenarios, but unfortunately this has the
         * effect that the privileged ones are ignored (and visible in the overlayfs mount). */
        _cleanup_free_ char *n = strjoin("user.overlay.", name);
        if (!n)
                return log_oom();

        r = xsetxattr(fd, /* path= */ NULL, AT_EMPTY_PATH, n, value);
        if (r < 0)
                return log_error_errno(r, "Failed to set '%s' xattr on file '%s': %m", n, path);

        return 0;
}

static int archive_unpack_whiteout(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *parent_path,      /* Full path of 'parent_fd', purely decorative for log purposes */
                const char *filename,         /* Just the filename we are supposed to whiteout */
                const char *path              /* Full path of the whiteout file, purely decorative for log purposes */) {

        int r;

        assert(a);
        assert(entry);
        assert(parent_fd >= 0);
        assert(parent_path);
        assert(filename);
        assert(path);

        _cleanup_free_ char *tmp = NULL;
        _cleanup_close_ int fd = open_tmpfile_linkable_at(parent_fd, filename, O_CLOEXEC|O_WRONLY, &tmp);
        if (fd < 0)
                return log_error_errno(fd, "Failed to create whiteout file for '%s': %m", path);

        CLEANUP_TMPFILE_AT(parent_fd, tmp);

        r = overlayfs_fsetfattr(path, fd, "whiteout", "y");
        if (r < 0)
                return r;

        /* As per https://docs.kernel.org/filesystems/overlayfs.html also mark the parent */
        r = overlayfs_fsetfattr(parent_path, parent_fd, "opaque", "x");
        if (r < 0)
                return r;

        r = link_tmpfile_at(fd, parent_fd, tmp, filename, LINK_TMPFILE_REPLACE);
        if (r < 0)
                return log_error_errno(r, "Failed to install regular file '%s': %m", path);

        tmp = mfree(tmp); /* disarm CLEANUP_TMPFILE_AT */
        return 0; /* we do not return an fd here, because this kills an inode, and doesn't synthesize one */
}

static int archive_unpack_opaque(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *parent_path) {

        assert(a);
        assert(entry);
        assert(parent_fd >= 0);
        assert(parent_path);

        /* we do not return an fd here either */

        return overlayfs_fsetfattr(parent_path, parent_fd, "opaque", "y");
}

static int archive_unpack_directory(
                struct archive *a,
                struct archive_entry *entry,
                int parent_fd,
                const char *filename,
                const char *path,
                unsigned fflags) {

        int r;

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

        if ((fflags & CHATTR_EARLY_FL) != 0) {
                r = chattr_full(fd,
                                /* path= */ NULL,
                                /* value= */ fflags,
                                /* mask= */ fflags & CHATTR_EARLY_FL,
                                /* ret_previous= */ NULL,
                                /* ret_final= */ NULL,
                                CHATTR_FALLBACK_BITWISE);
                if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        log_warning_errno(r, "Failed to apply chattr of '%s', ignoring: %m", path);
                else if (r < 0)
                        return log_error_errno(r, "Failed to adjust chattr of '%s': %m", path);
        }

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

static int archive_entry_read_acl(
                struct archive_entry *entry,
                acl_type_t ntype,
                acl_t *acl,
                TarFlags flags) {

        int r;

        assert(entry);
        assert(acl);

        int type;
        if (ntype == ACL_TYPE_ACCESS)
                type = ARCHIVE_ENTRY_ACL_TYPE_ACCESS;
        else if (ntype == ACL_TYPE_DEFAULT)
                type = ARCHIVE_ENTRY_ACL_TYPE_DEFAULT;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unexpected ACL type");

        int c = sym_archive_entry_acl_reset(entry, type);
        if (c == 0)
                return 0;
        assert(c > 0);

#if HAVE_ACL
        r = dlopen_libacl();
        if (r < 0) {
                log_debug_errno(r, "Not restoring ACL data on inode as libacl is not available: %m");
                return 0;
        }

        _cleanup_(acl_freep) acl_t a = NULL;
        a = sym_acl_init(c);
        if (!a)
                return log_oom();
#endif

        for (;;) {
                int rtype, permset, tag, qual;
                const char *name;
                r = sym_archive_entry_acl_next(
                                entry,
                                type,
                                &rtype,
                                &permset,
                                &tag,
                                &qual,
                                &name);
                if (r == ARCHIVE_EOF)
                        break;
                if (r != ARCHIVE_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Unexpected error while iterating through ACLs.");

                assert(rtype == type);

                static const struct {
                        int libarchive;
                        acl_tag_t libacl;
                } tag_map[] = {
                        { ARCHIVE_ENTRY_ACL_USER,      ACL_USER      },
                        { ARCHIVE_ENTRY_ACL_GROUP,     ACL_GROUP     },
                        { ARCHIVE_ENTRY_ACL_USER_OBJ,  ACL_USER_OBJ  },
                        { ARCHIVE_ENTRY_ACL_GROUP_OBJ, ACL_GROUP_OBJ },
                        { ARCHIVE_ENTRY_ACL_MASK,      ACL_MASK      },
                        { ARCHIVE_ENTRY_ACL_OTHER,     ACL_OTHER     },
                };

                acl_tag_t ntag = ACL_UNDEFINED_TAG;
                FOREACH_ELEMENT(t, tag_map)
                        if (t->libarchive == tag) {
                                ntag = t->libacl;
                                break;
                        }
                if (ntag == ACL_UNDEFINED_TAG)
                        continue;

#if HAVE_ACL
                acl_entry_t e;
                if (IN_SET(ntag, ACL_USER, ACL_GROUP)) {
                        id_t id = qual;
                        /* Suppress ACL entries for invalid  UIDs/GIDS */
                        if (!uid_is_valid(id))
                                continue;

                        /* Suppress ACL entries for UIDs/GIDs to squash */
                        if (FLAGS_SET(flags, TAR_SQUASH_UIDS_ABOVE_64K) && id >= NSRESOURCE_UIDS_64K)
                                continue;

                        if (sym_acl_create_entry(&a, &e) < 0)
                                return log_error_errno(errno, "Failed to create ACL entry: %m");

                        if (sym_acl_set_tag_type(e, ntag) < 0)
                                return log_error_errno(errno, "Failed to set ACL entry tag: %m");

                        if (sym_acl_set_qualifier(e, &id) < 0)
                                return log_error_errno(errno, "Failed to set ACL entry qualifier: %m");
                } else {
                        if (sym_acl_create_entry(&a, &e) < 0)
                                return log_error_errno(errno, "Failed to create ACL entry: %m");

                        if (sym_acl_set_tag_type(e, ntag) < 0)
                                return log_error_errno(errno, "Failed to set ACL entry tag: %m");
                }

                acl_permset_t p;
                if (sym_acl_get_permset(e, &p) < 0)
                        return log_error_errno(errno, "Failed to get ACL entry permission set: %m");

                r = acl_set_perm(p, ACL_READ, permset & ARCHIVE_ENTRY_ACL_READ);
                if (r < 0)
                        return log_error_errno(r, "Failed to set ACL entry read bit: %m");

                r = acl_set_perm(p, ACL_WRITE, permset & ARCHIVE_ENTRY_ACL_WRITE);
                if (r < 0)
                        return log_error_errno(r, "Failed to set ACL entry write bit: %m");

                r = acl_set_perm(p, ACL_EXECUTE, permset & ARCHIVE_ENTRY_ACL_EXECUTE);
                if (r < 0)
                        return log_error_errno(r, "Failed to set ACL entry execute bit: %m");

                if (sym_acl_set_permset(e, p) < 0)
                        return log_error_errno(errno, "Failed to set ACL entry permission set: %m");
#else
                *acl = POINTER_MAX; /* Indicate the entry has valid ACLs. */
                return 0;
#endif
        }

#if HAVE_ACL
        if (*acl)
                sym_acl_free(*acl);
        *acl = TAKE_PTR(a);
#else
        *acl = NULL; /* Indicate the entry has no ACL. */
#endif
        return 0;
}

static uid_t maybe_squash_uid(uid_t uid, TarFlags flags) {
        if (FLAGS_SET(flags, TAR_SQUASH_UIDS_ABOVE_64K) &&
            uid_is_valid(uid) &&
            uid >= NSRESOURCE_UIDS_64K)
                return UID_NOBODY;

        return uid;
}

static uid_t maybe_squash_gid(uid_t gid, TarFlags flags) {
        if (FLAGS_SET(flags, TAR_SQUASH_UIDS_ABOVE_64K) &&
            gid_is_valid(gid) &&
            gid >= NSRESOURCE_UIDS_64K)
                return GID_NOBODY;

        return gid;
}

static int archive_entry_read_stat(
                struct archive_entry *entry,
                mode_t *filetype,
                mode_t *mode,
                struct timespec *mtime,
                uid_t *uid,
                gid_t *gid,
                unsigned *fflags,
                acl_t *acl_access,
                acl_t *acl_default,
                XAttr **xa,
                size_t *n_xa,
                TarFlags flags) {

        int r;

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
                *uid = maybe_squash_uid(sym_archive_entry_uid(entry), flags);
        if (gid && sym_archive_entry_gid_is_set(entry))
                *gid = maybe_squash_gid(sym_archive_entry_gid(entry), flags);

        if (fflags) {
                unsigned long fs = 0, fc = 0;
                sym_archive_entry_fflags(entry, &fs, &fc);
                *fflags = (fs & ~fc) & CHATTR_TAR_FL;
        }

        (void) sym_archive_entry_xattr_reset(entry);
        for (;;) {
                const char *name = NULL;
                struct iovec data;
                r = sym_archive_entry_xattr_next(entry, &name, (const void**) &data.iov_base, &data.iov_len);
                if (r != ARCHIVE_OK)
                        break;

                assert(name);
                if (xattr_is_acl(name))
                        continue;

                if (!FLAGS_SET(flags, TAR_SELINUX) && xattr_is_selinux(name))
                        continue;

                bool duplicate = false;
                FOREACH_ARRAY(i, *xa, *n_xa)
                        if (streq(i->name, name)) {
                                duplicate = true;
                                break;
                        }
                if (duplicate)
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

        if (acl_access) {
                r = archive_entry_read_acl(entry, ACL_TYPE_ACCESS, acl_access, flags);
                if (r < 0)
                        return r;
        }

        if (acl_default) {
                r = archive_entry_read_acl(entry, ACL_TYPE_DEFAULT, acl_default, flags);
                if (r < 0)
                        return r;
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
                if (!IN_SET(ar, ARCHIVE_OK, ARCHIVE_WARN))
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Failed to parse archive: %s", sym_archive_error_string(a));

                const char *p = NULL;
                r = archive_entry_pathname_safe(entry, &p);
                if (r < 0)
                        return log_error_errno(r, "Invalid path name in entry, refusing.");
                if (ar == ARCHIVE_WARN)
                        log_warning("Non-critical error found while parsing '%s' from the archive, ignoring: %s", p ?: ".", sym_archive_error_string(a));

                if (!p) {
                        /* This is the root inode */
                        r = archive_entry_read_stat(
                                        entry,
                                        &open_inodes[0].filetype,
                                        &open_inodes[0].mode,
                                        &open_inodes[0].mtime,
                                        &open_inodes[0].uid,
                                        &open_inodes[0].gid,
                                        &open_inodes[0].fflags,
                                        &open_inodes[0].acl_access,
                                        &open_inodes[0].acl_default,
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
                        unsigned fflags = 0;
#if HAVE_ACL
                        _cleanup_(acl_freep)
#endif
                                acl_t acl_access = NULL, acl_default = NULL;
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
                                        r = chaseat(tree_fd, target, CHASE_PROHIBIT_SYMLINKS|CHASE_AT_RESOLVE_IN_ROOT|CHASE_NOFOLLOW, /* ret_path= */ NULL, &target_fd);
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
                                                r = chaseat(tree_fd, target, CHASE_PROHIBIT_SYMLINKS|CHASE_AT_RESOLVE_IN_ROOT|CHASE_PARENT|CHASE_EXTRACT_FILENAME|CHASE_NOFOLLOW, &target_filename, &target_parent_fd);
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
                                                &fflags,
                                                &acl_access,
                                                &acl_default,
                                                &xa,
                                                &n_xa,
                                                flags);
                                if (r < 0)
                                        return r;

                                switch (filetype) {

                                case S_IFREG:
                                        if (FLAGS_SET(flags, TAR_OCI_WHITEOUTS)) {
                                                if (streq(e, ".wh..wh..opq")) {
                                                        r = archive_unpack_opaque(a, entry, parent_fd, empty_to_root(parent_path));
                                                        if (r < 0)
                                                                return r;

                                                        /* NB: this does not create an inode! */
                                                        break;
                                                }

                                                const char *w = startswith(e, ".wh.");
                                                if (w) {
                                                        if (!filename_is_valid(w))
                                                                return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Invalid whiteout file entry '%s', refusing.", e);

                                                        r = archive_unpack_whiteout(a, entry, parent_fd, empty_to_root(parent_path), w, j);
                                                        if (r < 0)
                                                                return r;

                                                        /* NB: this does not create an inode! */
                                                        break;
                                                }
                                        }

                                        fd = archive_unpack_regular(a, entry, parent_fd, e, j, fflags);
                                        if (fd < 0)
                                                return fd;
                                        break;

                                case S_IFDIR:
                                        fd = archive_unpack_directory(a, entry, parent_fd, e, j, fflags);
                                        if (fd < 0)
                                                return fd;
                                        break;

                                case S_IFLNK:
                                        fd = archive_unpack_symlink(a, entry, parent_fd, e, j);
                                        if (fd < 0)
                                                return fd;
                                        break;

                                case S_IFCHR:
                                case S_IFBLK:
                                case S_IFIFO:
                                case S_IFSOCK:
                                        fd = archive_unpack_special_inode(a, entry, parent_fd, e, j, filetype);
                                        if (fd < 0)
                                                return fd;
                                        break;

                                default:
                                        return log_error_errno(
                                                        SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                                        "Unexpected file type %i of '%s', refusing.", (int) filetype, j);
                                }
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
                        if (fd >= 0) {
                                open_inodes[n_open_inodes++] = (OpenInode) {
                                        .fd = TAKE_FD(fd),
                                        .path = TAKE_PTR(j),
                                        .filetype = filetype,
                                        .mode = mode,
                                        .mtime = mtime,
                                        .uid = uid,
                                        .gid = gid,
                                        .fflags = fflags,
                                        .acl_access = TAKE_PTR(acl_access),
                                        .acl_default = TAKE_PTR(acl_default),
                                        .xattr = TAKE_PTR(xa),
                                        .n_xattr = n_xa,
                                };

                                n_xa = 0;
                        }
                }
        }

        r = open_inode_finalize_many(&open_inodes, &n_open_inodes);
        if (r < 0)
                return r;

        return 0;
}

static int make_tmpfs(void) {
        /* Creates a tmpfs superblock to store our hardlink db in. We can do this if we run in our own
         * userns, or if we are privileged. This is preferable, since it means the db is cleaned up
         * automatically once we are done. Moreover, since this is a new superblock owned by us, we do not
         * need to set up any uid mapping shenanigans */

        _cleanup_close_ int superblock_fd = fsopen("tmpfs", FSOPEN_CLOEXEC);
        if (superblock_fd < 0)
                return log_debug_errno(errno, "Failed to allocate tmpfs superblock: %m");

        (void) fsconfig(superblock_fd, FSCONFIG_SET_STRING, "source", "hardlink", /* aux= */ 0);
        (void) fsconfig(superblock_fd, FSCONFIG_SET_STRING, "mode", "0700", /* aux= */ 0);

        if (fsconfig(superblock_fd, FSCONFIG_CMD_CREATE, /* key= */ NULL, /* value= */ NULL, /* aux= */ 0) < 0)
                return log_debug_errno(errno, "Failed to finalize superblock: %m");

        _cleanup_close_ int mount_fd = fsmount(superblock_fd, FSMOUNT_CLOEXEC, MS_NODEV|MS_NOEXEC|MS_NOSUID);
        if (mount_fd < 0)
                return log_debug_errno(errno, "Failed to turn tmpfs superblock into mount: %m");

        return TAKE_FD(mount_fd);
}

struct make_archive_data {
        struct archive *archive;
        TarFlags flags;

        int hardlink_db_fd;
        char *hardlink_db_path;
        int have_unique_mount_id;
};

static int hardlink_lookup(
                struct make_archive_data *d,
                int inode_fd,
                const struct statx *sx,
                const char *path,
                char **ret) {

        _cleanup_free_ struct file_handle *handle = NULL;
        _cleanup_free_ char *m = NULL, *n = NULL;
        int r;

        assert(d);
        assert(inode_fd >= 0);
        assert(sx);

        /* If we know the hardlink count, and it's 1, then don't bother */
        if (FLAGS_SET(sx->stx_mask, STATX_NLINK) && sx->stx_nlink == 1)
                goto bypass;

        /* If this is a directory, then don't bother */
        if (FLAGS_SET(sx->stx_mask, STATX_TYPE) && !inode_type_can_hardlink(sx->stx_mode))
                goto bypass;

        uint64_t unique_mnt_id;
        int mnt_id;
        r = name_to_handle_at_try_fid(inode_fd, /* path= */ NULL,
                                      &handle,
                                      d->have_unique_mount_id <= 0 ? &mnt_id : NULL,
                                      d->have_unique_mount_id != 0 ? &unique_mnt_id : NULL,
                                      /* flags= */ AT_EMPTY_PATH);
        if (r < 0)
                return log_error_errno(r, "Failed to get file handle of file: %m");
        if (d->have_unique_mount_id < 0)
                d->have_unique_mount_id = r > 0;
        else
                assert(d->have_unique_mount_id == (r > 0));

        m = hexmem(SHA256_DIRECT(handle->f_handle, handle->handle_bytes), SHA256_DIGEST_SIZE);
        if (!m)
                return log_oom();

        if (d->have_unique_mount_id)
                r = asprintf(&n, "%" PRIu64 ":%i:%s", unique_mnt_id, handle->handle_type, m);
        else
                r = asprintf(&n, "%i:%i:%s", mnt_id, handle->handle_type, m);
        if (r < 0)
                return log_oom();

        if (d->hardlink_db_fd < 0) {
                assert(!d->hardlink_db_path);

                /* We first try to create our own superblock, which works if we are in a userns, and which
                 * doesn't require explicit clean-up */
                d->hardlink_db_fd = make_tmpfs();
                if (d->hardlink_db_fd < 0) {
                        log_debug_errno(d->hardlink_db_fd, "Failed to allocate tmpfs superblock for hardlink db, falling back to temporary directory: %m");

                        const char *vt;
                        r = var_tmp_dir(&vt);
                        if (r < 0)
                                return log_error_errno(r, "Failed to determine /var/tmp/ directory: %m");

                        _cleanup_free_ char *j = path_join(vt, "make-tar-XXXXXX");
                        if (!j)
                                return log_oom();

                        d->hardlink_db_fd = mkdtemp_open(j, /* flags= */ 0, &d->hardlink_db_path);
                        if (d->hardlink_db_fd < 0)
                                return log_error_errno(d->hardlink_db_fd, "Failed to make hardlink database directory: %m");
                }
        } else {
                _cleanup_free_ char *p = NULL;
                r = readlinkat_malloc(d->hardlink_db_fd, n, &p);
                if (r >= 0) {
                        /* Found previous hit! */
                        log_debug("hardlinkdb: found %s → %s", n, p);
                        *ret = TAKE_PTR(p);
                        return 1;
                }
                if (r != -ENOENT)
                        return log_error_errno(r, "Failed to read symlink '%s': %m", n);
        }

        /* Store information about this inode */
        if (symlinkat(path, d->hardlink_db_fd, n) < 0)
                return log_error_errno(errno, "Failed to create symlink '%s' → '%s': %m", n, path);

        log_debug("hardlinkdb: created %s → %s", n, path);

bypass:
        *ret = NULL;
        return 0;
}

static int archive_generate_sparse(struct archive_entry *entry, int fd) {
        assert(entry);
        assert(fd);

        off_t c = 0;
        for (;;) {
                /* Look for the next hole */
                off_t h = lseek(fd, c, SEEK_HOLE);
                if (h < 0) {
                        if (errno != ENXIO)
                                return log_error_errno(errno, "Failed to issue SEEK_HOLE: %m");

                        /* If errno == ENXIO, that means we've reached the final data of the file and
                         * that data isn't followed by anything more */

                        /* Figure out where the end of the file is */
                        off_t e = lseek(fd, 0, SEEK_END);
                        if (e < 0)
                                return log_error_errno(errno, "Failed to issue SEEK_END: %m");

                        /* Generate sparse entry for final block */
                        if (e > c && c != 0) {
                                log_debug("final sparse block %" PRIu64 "…%" PRIu64, (uint64_t) c, (uint64_t) e);
                                sym_archive_entry_sparse_add_entry(entry, c, e - c);
                        }

                        break;
                }

                if (h > c) {
                        log_debug("inner sparse block %" PRIu64 "…%" PRIu64 " (%" PRIu64 ")", (uint64_t) c, (uint64_t) h, (uint64_t) h - (uint64_t) c);
                        sym_archive_entry_sparse_add_entry(entry, c, h - c);
                }

                /* Now look for the next data after the hole */
                c = lseek(fd, h, SEEK_DATA);
                if (c < 0) {
                        if (errno != ENXIO)
                                return log_error_errno(errno, "Failed to issue SEEK_DATA: %m");

                        /* No data anymore */
                        break;
                }
        }

        if (lseek(fd, 0, SEEK_SET) < 0)
                return log_error_errno(errno, "Failed to reset seek offset: %m");

        return 0;
}

#if HAVE_ACL
static int archive_write_acl(
                struct archive_entry *entry,
                acl_type_t ntype,
                acl_t acl,
                TarFlags flags) {
        int r;

        assert(entry);
        assert(acl);

        int type;
        if (ntype == ACL_TYPE_ACCESS)
                type = ARCHIVE_ENTRY_ACL_TYPE_ACCESS;
        else if (ntype == ACL_TYPE_DEFAULT)
                type = ARCHIVE_ENTRY_ACL_TYPE_DEFAULT;
        else
                return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Unexpected ACL type");

        acl_entry_t e;
        r = sym_acl_get_entry(acl, ACL_FIRST_ENTRY, &e);
        for (;;) {
                if (r < 0)
                        return log_error_errno(errno, "Failed to get ACL entry: %m");
                if (r == 0)
                        break;

                acl_tag_t ntag;
                if (sym_acl_get_tag_type(e, &ntag) < 0)
                        return log_error_errno(errno, "Failed to get ACL entry tag: %m");

                static const int tag_map[] = {
                        [ACL_USER]      = ARCHIVE_ENTRY_ACL_USER,
                        [ACL_GROUP]     = ARCHIVE_ENTRY_ACL_GROUP,
                        [ACL_USER_OBJ]  = ARCHIVE_ENTRY_ACL_USER_OBJ,
                        [ACL_GROUP_OBJ] = ARCHIVE_ENTRY_ACL_GROUP_OBJ,
                        [ACL_MASK]      = ARCHIVE_ENTRY_ACL_MASK,
                        [ACL_OTHER]     = ARCHIVE_ENTRY_ACL_OTHER,
                };
                assert_cc(ACL_UNDEFINED_TAG == 0);   /* safety check, we assume that holes are filled with ACL_UNDEFINED_TAG */
                assert_cc(ELEMENTSOF(tag_map) <= 64); /* safety check, we assume that the tag ids are all packed and low */

                int tag = ntag >= 0 && ntag <= (acl_tag_t) ELEMENTSOF(tag_map) ? tag_map[ntag] : ACL_UNDEFINED_TAG;

                bool skip = false;
                id_t qualifier = UID_INVALID;
                if (IN_SET(ntag, ACL_USER, ACL_GROUP)) {
                        id_t *q = sym_acl_get_qualifier(e);
                        if (!q)
                                return log_error_errno(errno, "Failed to get ACL entry qualifier: %m");

                        qualifier = *q;
                        sym_acl_free(q);

                        /* Suppress invalid UIDs or those that shall be squashed */
                        skip = !(uid_is_valid(qualifier) &&
                                 (!FLAGS_SET(flags, TAR_SQUASH_UIDS_ABOVE_64K) || qualifier < NSRESOURCE_UIDS_64K));
                }

                if (!skip) {
                        acl_permset_t p;
                        if (sym_acl_get_permset(e, &p) < 0)
                                return log_error_errno(errno, "Failed to get ACL entry permission set: %m");

                        int permset = 0;
                        r = sym_acl_get_perm(p, ACL_READ);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get ACL entry read bit: %m");
                        SET_FLAG(permset, ARCHIVE_ENTRY_ACL_READ, r);

                        r = sym_acl_get_perm(p, ACL_WRITE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get ACL entry write bit: %m");
                        SET_FLAG(permset, ARCHIVE_ENTRY_ACL_WRITE, r);

                        r = sym_acl_get_perm(p, ACL_EXECUTE);
                        if (r < 0)
                                return log_error_errno(r, "Failed to get ACL entry execute bit: %m");
                        SET_FLAG(permset, ARCHIVE_ENTRY_ACL_EXECUTE, r);

                        r = sym_archive_entry_acl_add_entry(entry, type, permset, tag, qualifier, /* name= */ NULL);
                        if (r != ARCHIVE_OK)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to add ACL entry.");
                }

                r = sym_acl_get_entry(acl, ACL_NEXT_ENTRY, &e);
        }

        return 0;
}
#endif

static int archive_item(
                RecurseDirEvent event,
                const char *path,
                int dir_fd,
                int inode_fd,
                const struct dirent *de,
                const struct statx *sx,
                void *userdata) {

        struct make_archive_data *d = ASSERT_PTR(userdata);
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

        sym_archive_entry_set_pathname(entry, path);

        _cleanup_free_ char *hardlink = NULL;
        r = hardlink_lookup(d, inode_fd, sx, path, &hardlink);
        if (r < 0)
                return r;
        if (r > 0) {
                sym_archive_entry_set_hardlink(entry, hardlink);

                if (sym_archive_write_header(d->archive, entry) != ARCHIVE_OK)
                        return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to write archive entry header: %s", sym_archive_error_string(d->archive));

                return RECURSE_DIR_CONTINUE;
        }

        assert(FLAGS_SET(sx->stx_mask, STATX_TYPE|STATX_MODE));
        sym_archive_entry_set_filetype(entry, sx->stx_mode);

        if (!S_ISLNK(sx->stx_mode))
                sym_archive_entry_set_perm(entry, sx->stx_mode);

        if (FLAGS_SET(sx->stx_mask, STATX_UID))
                sym_archive_entry_set_uid(entry, maybe_squash_uid(sx->stx_uid, d->flags));
        if (FLAGS_SET(sx->stx_mask, STATX_GID))
                sym_archive_entry_set_gid(entry, maybe_squash_gid(sx->stx_gid, d->flags));

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

#if HAVE_ACL
        if (inode_type_can_acl(sx->stx_mode)) {

                r = dlopen_libacl();
                if (r < 0)
                        log_debug_errno(r, "No trying to read ACL off inode, as libacl support is not available: %m");
                else {
                        r = sym_acl_extended_file(FORMAT_PROC_FD_PATH(inode_fd));
                        if (r < 0 && !ERRNO_IS_NOT_SUPPORTED(errno))
                                return log_error_errno(errno, "Failed check if '%s' has ACLs: %m", path);
                        if (r > 0) {
                                _cleanup_(acl_freep) acl_t acl = NULL;
                                acl = sym_acl_get_file(FORMAT_PROC_FD_PATH(inode_fd), ACL_TYPE_ACCESS);
                                if (!acl)
                                        return log_error_errno(errno, "Failed read access ACLs of '%s': %m", path);

                                archive_write_acl(entry, ACL_TYPE_ACCESS, acl, d->flags);

                                if (S_ISDIR(sx->stx_mode)) {
                                        sym_acl_free(acl);

                                        acl = sym_acl_get_file(FORMAT_PROC_FD_PATH(inode_fd), ACL_TYPE_DEFAULT);
                                        if (!acl)
                                                return log_error_errno(errno, "Failed to read default ACLs of '%s': %m", path);

                                        archive_write_acl(entry, ACL_TYPE_DEFAULT, acl, d->flags);
                                }
                        }
                }
        }
#endif

        _cleanup_free_ char *xattrs = NULL;
        r = flistxattr_malloc(inode_fd, &xattrs);
        if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r) && r != -ENODATA)
                return log_error_errno(r, "Failed to read xattr list of '%s': %m", path);

        NULSTR_FOREACH(xa, xattrs) {
                _cleanup_free_ char *buf = NULL;
                size_t size;

                if (xattr_is_acl(xa))
                        continue;

                if (!FLAGS_SET(d->flags, TAR_SELINUX) && xattr_is_selinux(xa))
                        continue;

                r = fgetxattr_malloc(inode_fd, xa, &buf, &size);
                if (r == -ENODATA) /* deleted by now? ignore... */
                        continue;
                if (r < 0)
                        return log_error_errno(r, "Failed to read xattr '%s' of '%s': %m", xa, path);

                sym_archive_entry_xattr_add_entry(entry, xa, buf, size);
        }

        _cleanup_close_ int data_fd = -EBADF;
        if (S_ISREG(sx->stx_mode)) {
                /* Convert the O_PATH fd into a proper fd */
                data_fd = fd_reopen(inode_fd, O_RDONLY|O_CLOEXEC);
                if (data_fd < 0)
                        return log_error_errno(data_fd, "Failed to open '%s': %m", path);

                r = archive_generate_sparse(entry, data_fd);
                if (r < 0)
                        return r;
        }

        if (inode_type_can_chattr(sx->stx_mode)) {
                unsigned f = 0;

                r = read_attr_fd(data_fd >= 0 ? data_fd : inode_fd, &f);
                if (r < 0 && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                        return log_error_errno(r, "Failed to read file flags of '%s': %m", path);

                f &= CHATTR_TAR_FL;
                if (f != 0)
                        sym_archive_entry_set_fflags(entry, f, /* clear= */ 0);
        }

        if (sym_archive_write_header(d->archive, entry) != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to write archive entry header: %s", sym_archive_error_string(d->archive));

        if (S_ISREG(sx->stx_mode)) {
                assert(data_fd >= 0);

                for (;;) {
                        char buffer[64*1024];
                        ssize_t l;

                        l = read(data_fd, buffer, sizeof(buffer));
                        if (l < 0)
                                return log_error_errno(errno, "Failed to read '%s': %m",  path);
                        if (l == 0)
                                break;

                        la_ssize_t k;
                        k = sym_archive_write_data(d->archive, buffer, l);
                        if (k < 0)
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to write archive data: %s", sym_archive_error_string(d->archive));
                }
        }

        return RECURSE_DIR_CONTINUE;
}

static void make_archive_data_done(struct make_archive_data *d) {
        assert(d);

        if (d->hardlink_db_fd >= 0)
                (void) rm_rf_children(d->hardlink_db_fd, REMOVE_PHYSICAL, /* root_dev= */ NULL);

        unlink_and_free(d->hardlink_db_path);
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
                r = sym_archive_write_set_format_pax(a);
        if (r != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to set libarchive output format: %s", sym_archive_error_string(a));

        r = sym_archive_write_open_fd(a, output_fd);
        if (r != ARCHIVE_OK)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE), "Failed to set libarchive output file: %s", sym_archive_error_string(a));

        _cleanup_(make_archive_data_done) struct make_archive_data data = {
                .archive = a,
                .flags = flags,
                .hardlink_db_fd = -EBADF,
                .have_unique_mount_id = -1,
        };

        r = recurse_dir(tree_fd,
                        ".",
                        STATX_TYPE|STATX_MODE|STATX_UID|STATX_GID|STATX_SIZE|STATX_ATIME|STATX_CTIME,
                        UINT_MAX,
                        RECURSE_DIR_SORT|RECURSE_DIR_INODE_FD|RECURSE_DIR_TOPLEVEL,
                        archive_item,
                        &data);
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
