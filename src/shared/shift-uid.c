/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <linux/magic.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include "acl-util.h"
#include "alloc-util.h"
#include "dirent-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "log.h"
#include "shift-uid.h"
#include "stat-util.h"
#include "string-util.h"
#include "user-util.h"

/* While we are chmod()ing a directory tree, we set the top-level UID base to this "busy" base, so that we can always
 * recognize trees we are were chmod()ing recursively and got interrupted in */
#define UID_BUSY_BASE ((uid_t) UINT32_C(0xFFFE0000))
#define UID_BUSY_MASK ((uid_t) UINT32_C(0xFFFF0000))

#if HAVE_ACL

static int get_acl(int fd, const char *name, acl_type_t type, acl_t *ret) {
        acl_t acl;

        assert(fd >= 0);
        assert(ret);

        if (name) {
                _cleanup_close_ int child_fd = -EBADF;

                child_fd = openat(fd, name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (child_fd < 0)
                        return -errno;

                acl = sym_acl_get_file(FORMAT_PROC_FD_PATH(child_fd), type);
        } else if (type == ACL_TYPE_ACCESS)
                acl = sym_acl_get_fd(fd);
        else
                acl = sym_acl_get_file(FORMAT_PROC_FD_PATH(fd), type);
        if (!acl)
                return -errno;

        *ret = acl;
        return 0;
}

static int set_acl(int fd, const char *name, acl_type_t type, acl_t acl) {
        int r;

        assert(fd >= 0);
        assert(acl);

        if (name) {
                _cleanup_close_ int child_fd = -EBADF;

                child_fd = openat(fd, name, O_PATH|O_CLOEXEC|O_NOFOLLOW);
                if (child_fd < 0)
                        return -errno;

                r = sym_acl_set_file(FORMAT_PROC_FD_PATH(child_fd), type, acl);
        } else if (type == ACL_TYPE_ACCESS)
                r = sym_acl_set_fd(fd, acl);
        else
                r = sym_acl_set_file(FORMAT_PROC_FD_PATH(fd), type, acl);
        if (r < 0)
                return -errno;

        return 0;
}

static int shift_acl(acl_t acl, uid_t shift, acl_t *ret) {
        _cleanup_(acl_freep) acl_t copy = NULL;
        acl_entry_t i;
        int r;

        assert(acl);
        assert(ret);

        r = sym_acl_get_entry(acl, ACL_FIRST_ENTRY, &i);
        if (r < 0)
                return -errno;
        while (r > 0) {
                uid_t *old_uid, new_uid;
                bool modify = false;
                acl_tag_t tag;

                if (sym_acl_get_tag_type(i, &tag) < 0)
                        return -errno;

                if (IN_SET(tag, ACL_USER, ACL_GROUP)) {

                        /* We don't distinguish here between uid_t and gid_t, let's make sure the compiler checks that
                         * this is actually OK */
                        assert_cc(sizeof(uid_t) == sizeof(gid_t));

                        old_uid = sym_acl_get_qualifier(i);
                        if (!old_uid)
                                return -errno;

                        new_uid = shift | (*old_uid & UINT32_C(0xFFFF));
                        if (!uid_is_valid(new_uid))
                                return -EINVAL;

                        modify = new_uid != *old_uid;
                        if (modify && !copy) {
                                int n;

                                /* There's no copy of the ACL yet? if so, let's create one, and start the loop from the
                                 * beginning, so that we copy all entries, starting from the first, this time. */

                                n = sym_acl_entries(acl);
                                if (n < 0)
                                        return -errno;

                                copy = sym_acl_init(n);
                                if (!copy)
                                        return -errno;

                                /* Seek back to the beginning */
                                r = sym_acl_get_entry(acl, ACL_FIRST_ENTRY, &i);
                                if (r < 0)
                                        return -errno;
                                continue;
                        }
                }

                if (copy) {
                        acl_entry_t new_entry;

                        if (sym_acl_create_entry(&copy, &new_entry) < 0)
                                return -errno;

                        if (sym_acl_copy_entry(new_entry, i) < 0)
                                return -errno;

                        if (modify)
                                if (sym_acl_set_qualifier(new_entry, &new_uid) < 0)
                                        return -errno;
                }

                r = sym_acl_get_entry(acl, ACL_NEXT_ENTRY, &i);
                if (r < 0)
                        return -errno;
        }

        *ret = TAKE_PTR(copy);

        return !!*ret;
}

static int patch_acls(int fd, const char *name, const struct stat *st, uid_t shift) {
        _cleanup_(acl_freep) acl_t acl = NULL, shifted = NULL;
        bool changed = false;
        int r;

        assert(fd >= 0);
        assert(st);

        /* ACLs are not supported on symlinks, there's no point in trying */
        if (!inode_type_can_acl(st->st_mode))
                return 0;

        r = dlopen_libacl();
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return 0;
        if (r < 0)
                return r;

        r = get_acl(fd, name, ACL_TYPE_ACCESS, &acl);
        if (r == -EOPNOTSUPP)
                return 0;
        if (r < 0)
                return r;

        r = shift_acl(acl, shift, &shifted);
        if (r < 0)
                return r;
        if (r > 0) {
                r = set_acl(fd, name, ACL_TYPE_ACCESS, shifted);
                if (r < 0)
                        return r;

                changed = true;
        }

        if (S_ISDIR(st->st_mode)) {
                sym_acl_free(acl);

                if (shifted)
                        sym_acl_free(shifted);

                acl = shifted = NULL;

                r = get_acl(fd, name, ACL_TYPE_DEFAULT, &acl);
                if (r < 0)
                        return r;

                r = shift_acl(acl, shift, &shifted);
                if (r < 0)
                        return r;
                if (r > 0) {
                        r = set_acl(fd, name, ACL_TYPE_DEFAULT, shifted);
                        if (r < 0)
                                return r;

                        changed = true;
                }
        }

        return changed;
}

#else

static int patch_acls(int fd, const char *name, const struct stat *st, uid_t shift) {
        return 0;
}

#endif

static int patch_fd(int fd, const char *name, const struct stat *st, uid_t shift) {
        uid_t new_uid;
        gid_t new_gid;
        bool changed = false;
        int r;

        assert(fd >= 0);
        assert(st);

        new_uid =         shift | (st->st_uid & UINT32_C(0xFFFF));
        new_gid = (gid_t) shift | (st->st_gid & UINT32_C(0xFFFF));

        if (!uid_is_valid(new_uid) || !gid_is_valid(new_gid))
                return -EINVAL;

        if (st->st_uid != new_uid || st->st_gid != new_gid) {
                if (name)
                        r = fchownat(fd, name, new_uid, new_gid, AT_SYMLINK_NOFOLLOW);
                else
                        r = fchown(fd, new_uid, new_gid);
                if (r < 0)
                        return -errno;

                /* The Linux kernel alters the mode in some cases of chown(). Let's undo this. */
                if (name) {
                        if (!S_ISLNK(st->st_mode))
                                r = fchmodat(fd, name, st->st_mode, 0);
                        else /* Changing the mode of a symlink is not supported by Linux kernel. Don't bother. */
                                r = 0;
                } else
                        r = fchmod(fd, st->st_mode);
                if (r < 0)
                        return -errno;

                changed = true;
        }

        r = patch_acls(fd, name, st, shift);
        if (r < 0)
                return r;

        return r > 0 || changed;
}

/*
 * Check if the filesystem is fully compatible with user namespaces or
 * UID/GID patching. Some filesystems in this list can be fully mounted inside
 * user namespaces, however their inodes may relate to host resources or only
 * valid in the global user namespace, therefore no patching should be applied.
 */
static int is_fs_fully_userns_compatible(const struct statfs *sfs) {

        assert(sfs);

        return F_TYPE_EQUAL(sfs->f_type, BINFMTFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, CGROUP_SUPER_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, CGROUP2_SUPER_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, DEBUGFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, DEVPTS_SUPER_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, EFIVARFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, HUGETLBFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, MQUEUE_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, PROC_SUPER_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, PSTOREFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, SELINUX_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, SMACK_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, SECURITYFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, BPF_FS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, TRACEFS_MAGIC) ||
               F_TYPE_EQUAL(sfs->f_type, SYSFS_MAGIC);
}

static int recurse_fd(int fd, const struct stat *st, uid_t shift, bool is_toplevel) {
        _cleanup_closedir_ DIR *d = NULL;
        bool changed = false;
        struct statfs sfs;
        int r;

        assert(fd >= 0);

        if (fstatfs(fd, &sfs) < 0)
                return -errno;

        /* We generally want to permit crossing of mount boundaries when patching the UIDs/GIDs. However, we probably
         * shouldn't do this for /proc and /sys if that is already mounted into place. Hence, let's stop the recursion
         * when we hit procfs, sysfs or some other special file systems. */

        r = is_fs_fully_userns_compatible(&sfs);
        if (r < 0)
                return r;
        if (r > 0) {
                r = 0; /* don't recurse */
                return r;
        }

        /* Also, if we hit a read-only file system, then don't bother, skip the whole subtree */
        if ((sfs.f_flags & ST_RDONLY) ||
            access_fd(fd, W_OK) == -EROFS)
                goto read_only;

        if (S_ISDIR(st->st_mode)) {
                d = take_fdopendir(&fd);
                if (!d)
                        return -errno;

                FOREACH_DIRENT_ALL(de, d, return -errno) {
                        struct stat fst;

                        if (dot_or_dot_dot(de->d_name))
                                continue;

                        if (fstatat(dirfd(d), de->d_name, &fst, AT_SYMLINK_NOFOLLOW) < 0)
                                return -errno;

                        if (S_ISDIR(fst.st_mode)) {
                                int subdir_fd;

                                subdir_fd = openat(dirfd(d), de->d_name, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
                                if (subdir_fd < 0)
                                        return -errno;

                                r = recurse_fd(subdir_fd, &fst, shift, false);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        changed = true;

                        } else {
                                r = patch_fd(dirfd(d), de->d_name, &fst, shift);
                                if (r < 0)
                                        return r;
                                if (r > 0)
                                        changed = true;
                        }
                }
        }

        /* After we descended, also patch the directory itself. It's key to do this in this order so that the top-level
         * directory is patched as very last object in the tree, so that we can use it as quick indicator whether the
         * tree is properly chown()ed already. */
        r = patch_fd(d ? dirfd(d) : fd, NULL, st, shift);
        if (r == -EROFS)
                goto read_only;
        if (r > 0)
                changed = true;

        return changed;

read_only:
        if (!is_toplevel) {
                _cleanup_free_ char *name = NULL;

                /* When we hit a read-only subtree we simply skip it, but log about it. */
                (void) fd_get_path(fd, &name);
                log_debug("Skipping read-only file or directory %s.", strna(name));
                r = changed;
        }

        return r;
}

int path_patch_uid(const char *path, uid_t shift, uid_t range) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(path);

        fd = open(path, O_RDONLY|O_NONBLOCK|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW|O_NOATIME);
        if (fd < 0)
                return log_debug_errno(errno, "Failed to open '%s': %m", path);

        /* Recursively adjusts the UID/GIDs of all files of a directory tree. This is used to automatically fix up an
         * OS tree to the used user namespace UID range. Note that this automatic adjustment only works for UID ranges
         * following the concept that the upper 16-bit of a UID identify the container, and the lower 16-bit are the actual
         * UID within the container. */

        /* We only support containers where the shift starts at a 2^16 boundary */
        if ((shift & 0xFFFF) != 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "UID shift 0x%"PRIx32" is not at a 2^16 boundary.",
                                       (uint32_t) shift);

        if (shift == UID_BUSY_BASE)
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "UID shift 0x%"PRIx32" conflicts with busy base.",
                                       (uint32_t) shift);

        /* We only support containers with 16-bit UID ranges for the patching logic */
        if (range != 0x10000)
                return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                       "UID range 0x%"PRIx32" is not supported, must be 0x10000.",
                                       (uint32_t) range);

        if (fstat(fd, &st) < 0)
                return log_debug_errno(errno, "Failed to stat '%s': %m", path);

        /* We only support containers where the uid/gid container ID match */
        if ((uint32_t) st.st_uid >> 16 != (uint32_t) st.st_gid >> 16)
                return log_debug_errno(SYNTHETIC_ERRNO(EBADE),
                                       "UID container ID 0x%"PRIx32" does not match GID container ID 0x%"PRIx32".",
                                       (uint32_t) st.st_uid >> 16,
                                       (uint32_t) st.st_gid >> 16);

        /* Try to detect if the range is already right. Of course, this a pretty drastic optimization, as we assume
         * that if the top-level dir has the right upper 16-bit assigned, then everything below will have too... */
        if (((uint32_t) (st.st_uid ^ shift) >> 16) == 0)
                return 0;

        /* Before we start recursively chowning, mark the top-level dir as "busy" by chowning it to the "busy"
         * range. Should we be interrupted in the middle of our work, we'll see it owned by this user and will start
         * chown()ing it again, unconditionally, as the busy UID is not a valid UID we'd everpick for ourselves. */

        if ((st.st_uid & UID_BUSY_MASK) != UID_BUSY_BASE)
                if (fchown(fd,
                           UID_BUSY_BASE | (st.st_uid & ~UID_BUSY_MASK),
                           (gid_t) UID_BUSY_BASE | (st.st_gid & ~(gid_t) UID_BUSY_MASK)) < 0)
                        log_debug_errno(errno, "Failed to mark '%s' as busy, ignoring: %m", path);

        r = recurse_fd(TAKE_FD(fd), &st, shift, /* is_toplevel= */ true);
        if (r < 0)
                return log_debug_errno(r, "Failed to recursively patch UID/GID of '%s': %m", path);

        return r;
}
