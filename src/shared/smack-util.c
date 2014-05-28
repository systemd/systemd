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

#include <unistd.h>
#include <string.h>
#include <sys/xattr.h>

#include "smack-util.h"

bool use_smack(void) {
#ifdef HAVE_SMACK
        static int use_smack_cached = -1;

        if (use_smack_cached < 0)
                use_smack_cached = access("/sys/fs/smackfs/", F_OK) >= 0;

        return use_smack_cached;
#else
        return false;
#endif

}

int smack_label_path(const char *path, const char *label) {
#ifdef HAVE_SMACK
        if (!use_smack())
                return 0;

        if (label)
                return setxattr(path, "security.SMACK64", label, strlen(label), 0);
        else
                return lremovexattr(path, "security.SMACK64");
#else
        return 0;
#endif
}

int smack_label_fd(int fd, const char *label) {
#ifdef HAVE_SMACK
        if (!use_smack())
                return 0;

        return fsetxattr(fd, "security.SMACK64", label, strlen(label), 0);
#else
        return 0;
#endif
}

int smack_label_ip_out_fd(int fd, const char *label) {
#ifdef HAVE_SMACK
        if (!use_smack())
                return 0;

        return fsetxattr(fd, "security.SMACK64IPOUT", label, strlen(label), 0);
#else
        return 0;
#endif
}

int smack_label_ip_in_fd(int fd, const char *label) {
#ifdef HAVE_SMACK
        if (!use_smack())
                return 0;

        return fsetxattr(fd, "security.SMACK64IPIN", label, strlen(label), 0);
#else
        return 0;
#endif
}
