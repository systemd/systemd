/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

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

#include <errno.h>
#include <stdio.h>

#include "alloc-util.h"
#include "audit-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "macro.h"
#include "parse-util.h"
#include "process-util.h"
#include "user-util.h"
#include "util.h"

int audit_session_from_pid(pid_t pid, uint32_t *id) {
        _cleanup_free_ char *s = NULL;
        const char *p;
        uint32_t u;
        int r;

        assert(id);

        /* We don't convert ENOENT to ESRCH here, since we can't
         * really distuingish between "audit is not available in the
         * kernel" and "the process does not exist", both which will
         * result in ENOENT. */

        p = procfs_file_alloca(pid, "sessionid");

        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = safe_atou32(s, &u);
        if (r < 0)
                return r;

        if (u == AUDIT_SESSION_INVALID || u <= 0)
                return -ENODATA;

        *id = u;
        return 0;
}

int audit_loginuid_from_pid(pid_t pid, uid_t *uid) {
        _cleanup_free_ char *s = NULL;
        const char *p;
        uid_t u;
        int r;

        assert(uid);

        p = procfs_file_alloca(pid, "loginuid");

        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = parse_uid(s, &u);
        if (r == -ENXIO) /* the UID was -1 */
                return -ENODATA;
        if (r < 0)
                return r;

        *uid = (uid_t) u;
        return 0;
}

bool use_audit(void) {
        static int cached_use = -1;

        if (cached_use < 0) {
                int fd;

                fd = socket(AF_NETLINK, SOCK_RAW|SOCK_CLOEXEC|SOCK_NONBLOCK, NETLINK_AUDIT);
                if (fd < 0)
                        cached_use = errno != EAFNOSUPPORT && errno != EPROTONOSUPPORT;
                else {
                        cached_use = true;
                        safe_close(fd);
                }
        }

        return cached_use;
}
