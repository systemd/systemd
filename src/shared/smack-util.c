/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>
***/

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "label.h"
#include "label-util.h"
#include "log.h"
#include "path-util.h"
#include "process-util.h"
#include "smack-util.h"
#include "string-table.h"
#include "xattr-util.h"

#define SMACK_FLOOR_LABEL "_"
#define SMACK_STAR_LABEL  "*"

bool mac_smack_use(void) {
#if ENABLE_SMACK
        static int cached_use = -1;

        if (cached_use < 0)
                cached_use = access("/sys/fs/smackfs/", F_OK) >= 0;

        return cached_use;
#else
        return false;
#endif
}

#if ENABLE_SMACK

static const char* const smack_attr_table[_SMACK_ATTR_MAX] = {
        [SMACK_ATTR_ACCESS]     = "security.SMACK64",
        [SMACK_ATTR_EXEC]       = "security.SMACK64EXEC",
        [SMACK_ATTR_MMAP]       = "security.SMACK64MMAP",
        [SMACK_ATTR_TRANSMUTE]  = "security.SMACK64TRANSMUTE",
        [SMACK_ATTR_IPIN]       = "security.SMACK64IPIN",
        [SMACK_ATTR_IPOUT]      = "security.SMACK64IPOUT",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_TO_STRING(smack_attr, SmackAttr);

#endif

int mac_smack_read_at(int fd, const char *path, SmackAttr attr, char **ret) {
#if ENABLE_SMACK
        assert(fd >= 0 || fd == AT_FDCWD);
        assert(attr >= 0 && attr < _SMACK_ATTR_MAX);
        assert(ret);

        if (!mac_smack_use()) {
                *ret = NULL;
                return 0;
        }

        return getxattr_at_malloc(fd, path, smack_attr_to_string(attr), /* at_flags = */ 0, ret, /* ret_size= */ NULL);
#else
        return -EOPNOTSUPP;
#endif
}

int mac_smack_apply_at(int fd, const char *path, SmackAttr attr, const char *label) {
#if ENABLE_SMACK
        assert(fd >= 0 || fd == AT_FDCWD);
        assert(attr >= 0 && attr < _SMACK_ATTR_MAX);

        if (!mac_smack_use())
                return 0;

        if (!label)
                return xremovexattr(fd, path, /* at_flags = */ 0, smack_attr_to_string(attr));

        return xsetxattr(fd, path, /* at_flags = */ 0, smack_attr_to_string(attr), label);
#else
        return 0;
#endif
}

int mac_smack_apply_pid(pid_t pid, const char *label) {
#if ENABLE_SMACK
        const char *p;

        assert(pid >= 0);
        assert(label);

        if (!mac_smack_use())
                return 0;

        p = procfs_file_alloca(pid, "attr/current");
        return write_string_file(p, label, WRITE_STRING_FILE_DISABLE_BUFFER);
#else
        return 0;
#endif
}

#if ENABLE_SMACK

static int smack_fix_fd(
                int fd,
                const char *label_path,
                LabelFixFlags flags) {

        const char *label;
        struct stat st;
        int r;

        /* The caller should have done the sanity checks. */
        assert(fd >= 0);
        assert(label_path);
        assert(path_is_absolute(label_path));

        /* Path must be in /dev. */
        if (!path_startswith(label_path, "/dev"))
                return 0;

        if (fstat(fd, &st) < 0)
                return -errno;

        /*
         * Label directories and character devices "*".
         * Label symlinks "_".
         * Don't change anything else.
         */

        if (S_ISDIR(st.st_mode))
                label = SMACK_STAR_LABEL;
        else if (S_ISLNK(st.st_mode))
                label = SMACK_FLOOR_LABEL;
        else if (S_ISCHR(st.st_mode))
                label = SMACK_STAR_LABEL;
        else
                return 0;

        r = xsetxattr(fd, /* path = */ NULL, AT_EMPTY_PATH, "security.SMACK64", label);
        if (ERRNO_IS_NEG_NOT_SUPPORTED(r)) /* If the FS doesn't support labels, then exit without warning */
                return 0;
        if (r == -EROFS && FLAGS_SET(flags, LABEL_IGNORE_EROFS)) /* If the FS is read-only and we were told
                                                                    to ignore failures caused by that,
                                                                    suppress error */
                return 0;
        if (r < 0) {
                /* If the old label is identical to the new one, suppress any kind of error */
                _cleanup_free_ char *old_label = NULL;

                if (fgetxattr_malloc(fd, "security.SMACK64", &old_label, /* ret_size= */ NULL) >= 0 &&
                    streq(old_label, label))
                        return 0;

                return log_debug_errno(r, "Unable to fix SMACK label of '%s': %m", label_path);
        }

        return 0;
}

#endif

int mac_smack_fix_full(
                int atfd,
                const char *inode_path,
                const char *label_path,
                LabelFixFlags flags) {

#if ENABLE_SMACK
        _cleanup_close_ int opened_fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r, inode_fd;

        assert(atfd >= 0 || (atfd == AT_FDCWD && inode_path));

        if (!mac_smack_use())
                return 0;

        if (inode_path) {
                opened_fd = openat(atfd, inode_path, O_NOFOLLOW|O_CLOEXEC|O_PATH);
                if (opened_fd < 0) {
                        if (errno == ENOENT && FLAGS_SET(flags, LABEL_IGNORE_ENOENT))
                                return 0;

                        return -errno;
                }
                inode_fd = opened_fd;
        } else
                inode_fd = atfd;

        if (!label_path) {
                if (path_is_absolute(inode_path))
                        label_path = inode_path;
                else {
                        r = fd_get_path(inode_fd, &p);
                        if (r < 0)
                                return r;

                        label_path = p;
                }
        }

        return smack_fix_fd(inode_fd, label_path, flags);
#else
        return 0;
#endif
}

int mac_smack_fix(const char *path, LabelFixFlags flags) {
        return mac_smack_fix_full(AT_FDCWD, path, path, flags);
}

int renameat_and_apply_smack_floor_label(int fdf, const char *from, int fdt, const char *to) {

        assert(fdf >= 0 || fdf == AT_FDCWD);
        assert(fdt >= 0 || fdt == AT_FDCWD);

        if (renameat(fdf, from, fdt, to) < 0)
                return -errno;

#if HAVE_SMACK_RUN_LABEL
        return mac_smack_apply_at(fdt, to, SMACK_ATTR_ACCESS, SMACK_FLOOR_LABEL);
#else
        return 0;
#endif
}

static int mac_smack_label_pre(int dir_fd, const char *path, mode_t mode) {
        return 0;
}

static int mac_smack_label_post(int dir_fd, const char *path, bool created) {
        if (!created)
                return 0;

        return mac_smack_fix_full(dir_fd, path, NULL, 0);
}

int mac_smack_init(void) {
        static const LabelOps label_ops = {
                .pre = mac_smack_label_pre,
                .post = mac_smack_label_post,
        };

        if (!mac_smack_use())
                return 0;

        return label_ops_set(&label_ops);
}
