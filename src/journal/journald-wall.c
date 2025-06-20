/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "format-util.h"
#include "journald-manager.h"
#include "journald-wall.h"
#include "log.h"
#include "process-util.h"
#include "string-util.h"
#include "wall.h"

void manager_forward_wall(
                Manager *m,
                int priority,
                const char *identifier,
                const char *message,
                const struct ucred *ucred) {

        _cleanup_free_ char *ident_buf = NULL, *l_buf = NULL;
        const char *l;
        int r;

        assert(m);
        assert(message);

        if (LOG_PRI(priority) > m->config.max_level_wall)
                return;

        if (ucred) {
                if (!identifier) {
                        (void) pid_get_comm(ucred->pid, &ident_buf);
                        identifier = ident_buf;
                }

                if (asprintf(&l_buf, "%s["PID_FMT"]: %s", strempty(identifier), ucred->pid, message) < 0) {
                        log_oom();
                        return;
                }

                l = l_buf;

        } else if (identifier) {

                l = l_buf = strjoin(identifier, ": ", message);
                if (!l_buf) {
                        log_oom();
                        return;
                }
        } else
                l = message;

        r = wall(l, "systemd-journald", NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to send wall message: %m");
}
