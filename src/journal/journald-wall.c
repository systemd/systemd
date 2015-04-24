/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Sebastian Thorarensen

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

#include "utmp-wtmp.h"
#include "journald-server.h"
#include "journald-wall.h"
#include "formats-util.h"
#include "process-util.h"

void server_forward_wall(
                Server *s,
                int priority,
                const char *identifier,
                const char *message,
                const struct ucred *ucred) {

        _cleanup_free_ char *ident_buf = NULL, *l_buf = NULL;
        const char *l;
        int r;

        assert(s);
        assert(message);

        if (LOG_PRI(priority) > s->max_level_wall)
                return;

        if (ucred) {
                if (!identifier) {
                        get_process_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                if (asprintf(&l_buf, "%s["PID_FMT"]: %s", strempty(identifier), ucred->pid, message) < 0) {
                        log_oom();
                        return;
                }

                l = l_buf;

        } else if (identifier) {

                l = l_buf = strjoin(identifier, ": ", message, NULL);
                if (!l_buf) {
                        log_oom();
                        return;
                }
        } else
                l = message;

        r = utmp_wall(l, "systemd-journald", NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to send wall message: %m");
}
