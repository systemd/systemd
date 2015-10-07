/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Intel Corporation

  Author: Auke Kok <auke-jan.h.kok@intel.com>

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <sys/xattr.h>

#include "util.h"
#include "process-util.h"
#include "path-util.h"
#include "fileio.h"
#include "smack-util.h"

#ifdef HAVE_SMACK
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
        r = write_string_file(p, label, 0);
        if (r < 0)
                return r;

        return r;
}

int mac_smack_fix(const char *path, bool ignore_enoent, bool ignore_erofs) {
        struct stat st;
        int r = 0;

        assert(path);

        if (!mac_smack_use())
                return 0;

        /*
         * Path must be in /dev and must exist
         */
        if (!path_startswith(path, "/dev"))
                return 0;

        r = lstat(path, &st);
        if (r >= 0) {
                const char *label;

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

                r = lsetxattr(path, "security.SMACK64", label, strlen(label), 0);

                /* If the FS doesn't support labels, then exit without warning */
                if (r < 0 && errno == EOPNOTSUPP)
                        return 0;
        }

        if (r < 0) {
                /* Ignore ENOENT in some cases */
                if (ignore_enoent && errno == ENOENT)
                        return 0;

                if (ignore_erofs && errno == EROFS)
                        return 0;

                r = log_debug_errno(errno, "Unable to fix SMACK label of %s: %m", path);
        }

        return r;
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

int mac_smack_fix(const char *path, bool ignore_enoent, bool ignore_erofs) {
        return 0;
}

int mac_smack_copy(const char *dest, const char *src) {
        return 0;
}
#endif
