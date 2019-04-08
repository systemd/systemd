/* SPDX-License-Identifier: LGPL-2.1+ */
/***
  Copyright © 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>
***/

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/xattr.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "process-util.h"
#include "smack-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "xattr-util.h"

#if ENABLE_SMACK
bool mac_smack_use(void) {
        static int cached_use = -1;

        if (cached_use < 0)
                cached_use = access("/sys/fs/smackfs/", F_OK) >= 0;

        return cached_use;
}

static const char* const smack_attr_table[_SMACK_ATTR_MAX] = {
        [SMACK_ATTR_ACCESS]     = "security.SMACK64",
        [SMACK_ATTR_EXEC]       = "security.SMACK64EXEC",
        [SMACK_ATTR_MMAP]       = "security.SMACK64MMAP",
        [SMACK_ATTR_TRANSMUTE]  = "security.SMACK64TRANSMUTE",
        [SMACK_ATTR_IPIN]       = "security.SMACK64IPIN",
        [SMACK_ATTR_IPOUT]      = "security.SMACK64IPOUT",
};

DEFINE_STRING_TABLE_LOOKUP(smack_attr, SmackAttr);

int mac_smack_read(const char *path, SmackAttr attr, char **label) {
        assert(path);
        assert(attr >= 0 && attr < _SMACK_ATTR_MAX);
        assert(label);

        if (!mac_smack_use())
                return 0;

        return getxattr_malloc(path, smack_attr_to_string(attr), label, true);
}

int mac_smack_read_fd(int fd, SmackAttr attr, char **label) {
        assert(fd >= 0);
        assert(attr >= 0 && attr < _SMACK_ATTR_MAX);
        assert(label);

        if (!mac_smack_use())
                return 0;

        return fgetxattr_malloc(fd, smack_attr_to_string(attr), label);
}

int mac_smack_apply(const char *path, SmackAttr attr, const char *label) {
        int r;

        assert(path);
        assert(attr >= 0 && attr < _SMACK_ATTR_MAX);

        if (!mac_smack_use())
                return 0;

        if (label)
                r = lsetxattr(path, smack_attr_to_string(attr), label, strlen(label), 0);
        else
                r = lremovexattr(path, smack_attr_to_string(attr));
        if (r < 0)
                return -errno;

        return 0;
}

int mac_smack_apply_fd(int fd, SmackAttr attr, const char *label) {
        int r;

        assert(fd >= 0);
        assert(attr >= 0 && attr < _SMACK_ATTR_MAX);

        if (!mac_smack_use())
                return 0;

        if (label)
                r = fsetxattr(fd, smack_attr_to_string(attr), label, strlen(label), 0);
        else
                r = fremovexattr(fd, smack_attr_to_string(attr));
        if (r < 0)
                return -errno;

        return 0;
}

int mac_smack_apply_pid(pid_t pid, const char *label) {
        const char *p;
        int r = 0;

        assert(label);

        if (!mac_smack_use())
                return 0;

        p = procfs_file_alloca(pid, "attr/current");
        r = write_string_file(p, label, WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return r;

        return r;
}

static int smack_fix_fd(int fd , const char *abspath, LabelFixFlags flags) {
        char procfs_path[STRLEN("/proc/self/fd/") + DECIMAL_STR_MAX(int)];
        const char *label;
        struct stat st;
        int r;

        /* The caller should have done the sanity checks. */
        assert(abspath);
        assert(path_is_absolute(abspath));

        /* Path must be in /dev. */
        if (!path_startswith(abspath, "/dev"))
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

        xsprintf(procfs_path, "/proc/self/fd/%i", fd);
        if (setxattr(procfs_path, "security.SMACK64", label, strlen(label), 0) < 0) {
                _cleanup_free_ char *old_label = NULL;

                r = -errno;

                /* If the FS doesn't support labels, then exit without warning */
                if (r == -EOPNOTSUPP)
                        return 0;

                /* It the FS is read-only and we were told to ignore failures caused by that, suppress error */
                if (r == -EROFS && (flags & LABEL_IGNORE_EROFS))
                        return 0;

                /* If the old label is identical to the new one, suppress any kind of error */
                if (getxattr_malloc(procfs_path, "security.SMACK64", &old_label, false) >= 0 &&
                    streq(old_label, label))
                        return 0;

                return log_debug_errno(r, "Unable to fix SMACK label of %s: %m", abspath);
        }

        return 0;
}

int mac_smack_fix_at(int dirfd, const char *path, LabelFixFlags flags) {
        _cleanup_free_ char *p = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);

        if (!mac_smack_use())
                return 0;

        fd = openat(dirfd, path, O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (fd < 0) {
                if ((flags & LABEL_IGNORE_ENOENT) && errno == ENOENT)
                        return 0;

                return -errno;
        }

        if (!path_is_absolute(path)) {
                r = fd_get_path(fd, &p);
                if (r < 0)
                        return r;
                path = p;
        }

        return smack_fix_fd(fd, path, flags);
}

int mac_smack_fix(const char *path, LabelFixFlags flags) {
        _cleanup_free_ char *abspath = NULL;
        _cleanup_close_ int fd = -1;
        int r;

        assert(path);

        if (!mac_smack_use())
                return 0;

        r = path_make_absolute_cwd(path, &abspath);
        if (r < 0)
                return r;

        fd = open(abspath, O_NOFOLLOW|O_CLOEXEC|O_PATH);
        if (fd < 0) {
                if ((flags & LABEL_IGNORE_ENOENT) && errno == ENOENT)
                        return 0;

                return -errno;
        }

        return smack_fix_fd(fd, abspath, flags);
}

int mac_smack_copy(const char *dest, const char *src) {
        int r = 0;
        _cleanup_free_ char *label = NULL;

        assert(dest);
        assert(src);

        r = mac_smack_read(src, SMACK_ATTR_ACCESS, &label);
        if (r < 0)
                return r;

        r = mac_smack_apply(dest, SMACK_ATTR_ACCESS, label);
        if (r < 0)
                return r;

        return r;
}

#else
bool mac_smack_use(void) {
        return false;
}

int mac_smack_read(const char *path, SmackAttr attr, char **label) {
        return -EOPNOTSUPP;
}

int mac_smack_read_fd(int fd, SmackAttr attr, char **label) {
        return -EOPNOTSUPP;
}

int mac_smack_apply(const char *path, SmackAttr attr, const char *label) {
        return 0;
}

int mac_smack_apply_fd(int fd, SmackAttr attr, const char *label) {
        return 0;
}

int mac_smack_apply_pid(pid_t pid, const char *label) {
        return 0;
}

int mac_smack_fix(const char *path, LabelFixFlags flags) {
        return 0;
}

int mac_smack_fix_at(int dirfd, const char *path, LabelFixFlags flags) {
        return 0;
}

int mac_smack_copy(const char *dest, const char *src) {
        return 0;
}
#endif
