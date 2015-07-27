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

#define SMACK_FLOOR_LABEL "_"
#define SMACK_STAR_LABEL  "*"

bool mac_smack_use(void) {
#ifdef HAVE_SMACK
        static int cached_use = -1;

        if (cached_use < 0)
                cached_use = access("/sys/fs/smackfs/", F_OK) >= 0;

        return cached_use;
#else
        return false;
#endif
}

#ifdef HAVE_SMACK
static int mac_get_xattr(const char *path, const char *attr, const char **label) {
        char l[NAME_MAX] = "", *ll = NULL;
        ssize_t s = 0;

        assert(path);
        assert(attr);
        assert(label);

        if (!mac_smack_use())
                return 0;

        s = getxattr(path, attr, l, NAME_MAX);
        if (s < 0)
                return -errno;

        ll = strdup(l);
        if (!ll)
                return -ENOMEM;

        *label = ll;

        return s;
}

static int mac_get_xattr_fd(int fd, const char *attr, const char **label) {
        char l[NAME_MAX] = "", *ll = NULL;
        ssize_t s = 0;

        assert(fd >= 0);
        assert(attr);
        assert(label);

        if (!mac_smack_use())
                return 0;

        s = fgetxattr(fd, attr, l, NAME_MAX);
        if (s < 0)
                return -errno;

        ll = strdup(l);
        if (!ll)
                return -ENOMEM;

        *label = ll;

        return s;
}

static int mac_set_xattr(const char *path, const char *attr, const char *label) {
        int r;

        assert(path);
        assert(attr);

        if (!mac_smack_use())
                return 0;

        if (label)
                r = lsetxattr(path, attr, label, strlen(label), 0);
        else
                r = lremovexattr(path, attr);
        if (r < 0)
                return -errno;

        return 0;
}

static int mac_set_xattr_fd(int fd, const char *attr, const char *label) {
        int r;

        assert(fd >= 0);
        assert(attr);

        if (!mac_smack_use())
                return 0;

        if (label)
                r = fsetxattr(fd, attr, label, strlen(label), 0);
        else
                r = fremovexattr(fd, attr);
        if (r < 0)
                return -errno;

        return 0;
}
#else
static int mac_get_xattr(const char *path, const char *attr, const char **label) {
        return 0;
}

static int mac_get_xattr_fd(int fd, const char *attr, const char **label) {
        return 0;
}

static int mac_set_xattr(const char *path, const char *attr, const char *label) {
        return 0;
}

static int mac_set_xattr_fd(int fd, const char *attr, const char *label) {
        return 0;
}
#endif

int mac_smack_read(const char *path, const char **label) {
        assert(path);
        assert(label);

        return mac_get_xattr(path, "security.SMACK64", label);
}

int mac_smack_apply(const char *path, const char *label) {
        assert(path);

        return mac_set_xattr(path, "security.SMACK64", label);
}

int mac_smack_read_fd(int fd, const char **label) {
        assert(fd >= 0);
        assert(label);

        return mac_get_xattr_fd(fd, "security.SMACK64", label);
}

int mac_smack_apply_fd(int fd, const char *label) {
        assert(fd >= 0);

        return mac_set_xattr_fd(fd, "security.SMACK64", label);
}

int mac_smack_read_exec(const char *path, const char **label) {
        assert(path);
        assert(label);

        return mac_get_xattr(path, "security.SMACK64EXEC", label);
}

int mac_smack_apply_exec(const char *path, const char *label) {
        assert(path);

        return mac_set_xattr(path, "security.SMACK64EXEC", label);
}

int mac_smack_read_exec_fd(int fd, const char **label) {
        assert(fd >= 0);
        assert(label);

        return mac_get_xattr_fd(fd, "security.SMACK64EXEC", label);
}

int mac_smack_apply_exec_fd(int fd, const char *label) {
        assert(fd >= 0);

        return mac_set_xattr_fd(fd, "security.SMACK64EXEC", label);
}

int mac_smack_read_ip_out(const char *path, const char **label) {
        assert(path);
        assert(label);

        return mac_get_xattr(path, "security.SMACK64IPOUT", label);
}

int mac_smack_apply_ip_out(const char *path, const char *label) {
        assert(path);

        return mac_set_xattr(path, "security.SMACK64IPOUT", label);
}

int mac_smack_read_ip_out_fd(int fd, const char **label) {
        assert(fd >= 0);
        assert(label);

        return mac_get_xattr_fd(fd, "security.SMACK64IPOUT", label);
}

int mac_smack_apply_ip_out_fd(int fd, const char *label) {
        assert(fd >= 0);

        return mac_set_xattr_fd(fd, "security.SMACK64IPOUT", label);
}

int mac_smack_read_ip_in(const char *path, const char **label) {
        assert(path);
        assert(label);

        return mac_get_xattr(path, "security.SMACK64IPIN", label);
}

int mac_smack_apply_ip_in(const char *path, const char *label) {
        assert(path);

        return mac_set_xattr(path, "security.SMACK64IPIN", label);
}

int mac_smack_read_ip_in_fd(int fd, const char **label) {
        assert(fd >= 0);
        assert(label);

        return mac_get_xattr_fd(fd, "security.SMACK64IPIN", label);
}

int mac_smack_apply_ip_in_fd(int fd, const char *label) {
        assert(fd >= 0);

        return mac_set_xattr_fd(fd, "security.SMACK64IPIN", label);
}

int mac_smack_apply_pid(pid_t pid, const char *label) {

#ifdef HAVE_SMACK
        const char *p;
#endif
        int r = 0;

        assert(label);

#ifdef HAVE_SMACK
        if (!mac_smack_use())
                return 0;

        p = procfs_file_alloca(pid, "attr/current");
        r = write_string_file(p, label, 0);
        if (r < 0)
                return r;
#endif

        return r;
}

int mac_smack_fix(const char *path, bool ignore_enoent, bool ignore_erofs) {

#ifdef HAVE_SMACK
        struct stat st;
#endif
        int r = 0;

        assert(path);

#ifdef HAVE_SMACK
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
#endif

        return r;
}
