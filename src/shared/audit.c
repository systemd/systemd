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

#include "macro.h"
#include "audit.h"
#include "util.h"
#include "log.h"
#include "fileio.h"
#include "virt.h"

int audit_session_from_pid(pid_t pid, uint32_t *id) {
        _cleanup_free_ char *s = NULL;
        const char *p;
        uint32_t u;
        int r;

        assert(id);

        p = procfs_file_alloca(pid, "sessionid");

        r = read_one_line_file(p, &s);
        if (r < 0)
                return r;

        r = safe_atou32(s, &u);
        if (r < 0)
                return r;

        if (u == (uint32_t) -1 || u <= 0)
                return -ENXIO;

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
        if (r < 0)
                return r;

        *uid = (uid_t) u;
        return 0;
}
