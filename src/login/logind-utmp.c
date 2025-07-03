/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/inotify.h>

#include "sd-event.h"

#include "log.h"
#include "logind.h"
#include "logind-session.h"
#include "logind-utmp.h"
#include "path-util.h"
#include "process-util.h"
#include "utmp-wtmp.h"

int manager_read_utmp(Manager *m) {
#if ENABLE_UTMP
        assert(m);

        if (utmpxname(UTMPX_FILE) < 0)
                return log_error_errno(errno, "Failed to set utmp path to " UTMPX_FILE ": %m");

        _unused_ _cleanup_(utxent_cleanup) bool utmpx = utxent_start();

        for (;;) {
                _cleanup_free_ char *t = NULL;
                struct utmpx *u;
                const char *c;
                Session *s;

                errno = 0;
                u = getutxent();
                if (!u) {
                        if (errno == ENOENT)
                                log_debug_errno(errno, UTMPX_FILE " does not exist, ignoring.");
                        else if (errno != 0)
                                log_warning_errno(errno, "Failed to read " UTMPX_FILE ", ignoring: %m");
                        return 0;
                }

                if (u->ut_type != USER_PROCESS)
                        continue;

                if (!pid_is_valid(u->ut_pid))
                        continue;

                t = memdup_suffix0(u->ut_line, sizeof(u->ut_line));
                if (!t)
                        return log_oom();

                c = path_startswith(t, "/dev/");
                if (c) {
                        if (free_and_strdup(&t, c) < 0)
                                return log_oom();
                }

                if (isempty(t))
                        continue;

                if (manager_get_session_by_leader(m, &PIDREF_MAKE_FROM_PID(u->ut_pid), &s) <= 0)
                        continue;

                if (s->type != SESSION_TTY)
                        continue;

                if (s->tty_validity == TTY_FROM_UTMP && !streq_ptr(s->tty, t)) {
                        /* This may happen on multiplexed SSH connection (i.e. 'SSH connection sharing'). In
                         * this case PAM and utmp sessions don't match. In such a case let's invalidate the TTY
                         * information and never acquire it again. */

                        s->tty = mfree(s->tty);
                        s->tty_validity = TTY_UTMP_INCONSISTENT;
                        log_debug("Session '%s' has inconsistent TTY information, dropping TTY information.", s->id);
                        session_save(s);
                        continue;
                }

                /* Never override what we figured out once */
                if (s->tty || s->tty_validity >= 0)
                        continue;

                s->tty = TAKE_PTR(t);
                s->tty_validity = TTY_FROM_UTMP;
                log_debug("Acquired TTY information '%s' from utmp for session '%s'.", s->tty, s->id);
                session_save(s);
        }

#else
        return 0;
#endif
}

#if ENABLE_UTMP
static int manager_dispatch_utmp(sd_event_source *s, const struct inotify_event *event, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        /* If there's indication the file itself might have been removed or became otherwise unavailable, then let's
         * reestablish the watch on whatever there's now. */
        if ((event->mask & (IN_ATTRIB|IN_DELETE_SELF|IN_MOVE_SELF|IN_Q_OVERFLOW|IN_UNMOUNT)) != 0)
                manager_connect_utmp(m);

        (void) manager_read_utmp(m);
        return 0;
}
#endif

void manager_connect_utmp(Manager *m) {
#if ENABLE_UTMP
        sd_event_source *s = NULL;
        int r;

        assert(m);

        /* Watch utmp for changes via inotify. We do this to deal with tools such as ssh, which will register the PAM
         * session early, and acquire a TTY only much later for the connection. Thus during PAM the TTY won't be known
         * yet. ssh will register itself with utmp when it finally acquired the TTY. Hence, let's make use of this, and
         * watch utmp for the TTY asynchronously. We use the PAM session's leader PID as key, to find the right entry.
         *
         * Yes, relying on utmp is pretty ugly, but it's good enough for informational purposes, as well as idle
         * detection (which, for tty sessions, relies on the TTY used) */

        r = sd_event_add_inotify(m->event, &s, UTMPX_FILE, IN_MODIFY|IN_MOVE_SELF|IN_DELETE_SELF|IN_ATTRIB, manager_dispatch_utmp, m);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG: LOG_WARNING, r, "Failed to create inotify watch on " UTMPX_FILE ", ignoring: %m");
        else {
                r = sd_event_source_set_priority(s, SD_EVENT_PRIORITY_IDLE);
                if (r < 0)
                        log_warning_errno(r, "Failed to adjust utmp event source priority, ignoring: %m");

                (void) sd_event_source_set_description(s, "utmp");
        }

        sd_event_source_unref(m->utmp_event_source);
        m->utmp_event_source = s;
#endif
}

void manager_reconnect_utmp(Manager *m) {
#if ENABLE_UTMP
        assert(m);

        if (m->utmp_event_source)
                return;

        manager_connect_utmp(m);
#endif
}
