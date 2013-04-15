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

#include <assert.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <sys/prctl.h>
#include <sys/capability.h>

#include "macro.h"
#include "audit.h"
#include "util.h"
#include "log.h"
#include "fileio.h"
#include "virt.h"

int audit_session_from_pid(pid_t pid, uint32_t *id) {
        char *s;
        uint32_t u;
        int r;

        assert(id);

        if (have_effective_cap(CAP_AUDIT_CONTROL) <= 0)
                return -ENOENT;

        /* Audit doesn't support containers right now */
        if (detect_container(NULL) > 0)
                return -ENOTSUP;

        if (pid == 0)
                r = read_one_line_file("/proc/self/sessionid", &s);
        else {
                char *p;

                if (asprintf(&p, "/proc/%lu/sessionid", (unsigned long) pid) < 0)
                        return -ENOMEM;

                r = read_one_line_file(p, &s);
                free(p);
        }

        if (r < 0)
                return r;

        r = safe_atou32(s, &u);
        free(s);

        if (r < 0)
                return r;

        if (u == (uint32_t) -1 || u <= 0)
                return -ENOENT;

        *id = u;
        return 0;
}

int audit_loginuid_from_pid(pid_t pid, uid_t *uid) {
        char *s;
        uid_t u;
        int r;

        assert(uid);

        /* Only use audit login uid if we are executed with sufficient
         * capabilities so that pam_loginuid could do its job. If we
         * are lacking the CAP_AUDIT_CONTROL capabality we most likely
         * are being run in a container and /proc/self/loginuid is
         * useless since it probably contains a uid of the host
         * system. */

        if (have_effective_cap(CAP_AUDIT_CONTROL) <= 0)
                return -ENOENT;

        /* Audit doesn't support containers right now */
        if (detect_container(NULL) > 0)
                return -ENOTSUP;

        if (pid == 0)
                r = read_one_line_file("/proc/self/loginuid", &s);
        else {
                char *p;

                if (asprintf(&p, "/proc/%lu/loginuid", (unsigned long) pid) < 0)
                        return -ENOMEM;

                r = read_one_line_file(p, &s);
                free(p);
        }

        if (r < 0)
                return r;

        r = parse_uid(s, &u);
        free(s);

        if (r < 0)
                return r;

        if (u == (uid_t) -1)
                return -ENOENT;

        *uid = (uid_t) u;
        return 0;
}
