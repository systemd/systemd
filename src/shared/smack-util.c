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
#include "path-util.h"
#include "smack-util.h"

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

int mac_smack_set_path(const char *path, const char *label) {
#ifdef HAVE_SMACK
        if (!mac_smack_use())
                return 0;

        if (label)
                return setxattr(path, "security.SMACK64", label, strlen(label), 0);
        else
                return lremovexattr(path, "security.SMACK64");
#else
        return 0;
#endif
}

int mac_smack_set_fd(int fd, const char *label) {
#ifdef HAVE_SMACK
        if (!mac_smack_use())
                return 0;

        return fsetxattr(fd, "security.SMACK64", label, strlen(label), 0);
#else
        return 0;
#endif
}

int mac_smack_set_ip_out_fd(int fd, const char *label) {
#ifdef HAVE_SMACK
        if (!mac_smack_use())
                return 0;

        return fsetxattr(fd, "security.SMACK64IPOUT", label, strlen(label), 0);
#else
        return 0;
#endif
}

int mac_smack_set_ip_in_fd(int fd, const char *label) {
#ifdef HAVE_SMACK
        if (!mac_smack_use())
                return 0;

        return fsetxattr(fd, "security.SMACK64IPIN", label, strlen(label), 0);
#else
        return 0;
#endif
}

int mac_smack_relabel_in_dev(const char *path) {
        int r = 0;

#ifdef HAVE_SMACK
        struct stat sb;
        const char *label;

        /*
         * Path must be in /dev and must exist
         */
        if (!path_startswith(path, "/dev"))
                return 0;

        r = lstat(path, &sb);
        if (r < 0)
                return -errno;

        /*
         * Label directories and character devices "*".
         * Label symlinks "_".
         * Don't change anything else.
         */
        if (S_ISDIR(sb.st_mode))
                label = SMACK_STAR_LABEL;
        else if (S_ISLNK(sb.st_mode))
                label = SMACK_FLOOR_LABEL;
        else if (S_ISCHR(sb.st_mode))
                label = SMACK_STAR_LABEL;
        else
                return 0;

        r = setxattr(path, "security.SMACK64", label, strlen(label), 0);
        if (r < 0) {
                log_error("Smack relabeling \"%s\" %m", path);
                return -errno;
        }
#endif

        return r;
}
