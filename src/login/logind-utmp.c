/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Daniel Mack

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
#include <string.h>
#include <unistd.h>
#include <pwd.h>

#include "sd-messages.h"
#include "strv.h"
#include "special.h"
#include "unit-name.h"
#include "audit.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-common-errors.h"
#include "logind.h"
#include "formats-util.h"
#include "utmp-wtmp.h"

_const_ static usec_t when_wall(usec_t n, usec_t elapse) {

        usec_t left;
        unsigned int i;
        static const int wall_timers[] = {
                0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                25, 40, 55, 70, 100, 130, 150, 180,
        };

        /* If the time is already passed, then don't announce */
        if (n >= elapse)
                return 0;

        left = elapse - n;

        for (i = 1; i < ELEMENTSOF(wall_timers); i++)
                if (wall_timers[i] * USEC_PER_MINUTE >= left)
                        return left - wall_timers[i-1] * USEC_PER_MINUTE;

        return left % USEC_PER_HOUR;
}

bool logind_wall_tty_filter(const char *tty, void *userdata) {

        Manager *m = userdata;

        assert(m);

        if (!startswith(tty, "/dev/"))
                return true;

        return !streq(tty + 5, m->scheduled_shutdown_tty);
}

static int warn_wall(Manager *m, usec_t n) {
        char date[FORMAT_TIMESTAMP_MAX] = {};
        _cleanup_free_ char *l = NULL;
        usec_t left;
        int r;

        assert(m);

        if (!m->enable_wall_messages)
                return 0;

        left = m->scheduled_shutdown_timeout > n;

        r = asprintf(&l, "%s%sThe system is going down for %s %s%s!",
                     strempty(m->wall_message),
                     isempty(m->wall_message) ? "" : "\n",
                     m->scheduled_shutdown_type,
                     left ? "at " : "NOW",
                     left ? format_timestamp(date, sizeof(date), m->scheduled_shutdown_timeout) : "");
        if (r < 0) {
                log_oom();
                return 0;
        }

        utmp_wall(l, lookup_uid(m->scheduled_shutdown_uid),
                  m->scheduled_shutdown_tty, logind_wall_tty_filter, m);

        return 1;
}

static int wall_message_timeout_handler(
                        sd_event_source *s,
                        uint64_t usec,
                        void *userdata) {

        Manager *m = userdata;
        usec_t n, next;
        int r;

        assert(m);
        assert(s == m->wall_message_timeout_source);

        n = now(CLOCK_REALTIME);

        r = warn_wall(m, n);
        if (r == 0)
                return 0;

        next = when_wall(n, m->scheduled_shutdown_timeout);
        if (next > 0) {
                r = sd_event_source_set_time(s, n + next);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_time() failed. %m");

                r = sd_event_source_set_enabled(s, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_enabled() failed. %m");
        }

        return 0;
}

int manager_setup_wall_message_timer(Manager *m) {

        usec_t n, elapse;
        int r;

        assert(m);

        n = now(CLOCK_REALTIME);
        elapse = m->scheduled_shutdown_timeout;

        /* wall message handling */

        if (isempty(m->scheduled_shutdown_type)) {
                warn_wall(m, n);
                return 0;
        }

        if (elapse < n)
                return 0;

        /* Warn immediately if less than 15 minutes are left */
        if (elapse - n < 15 * USEC_PER_MINUTE) {
                r = warn_wall(m, n);
                if (r == 0)
                        return 0;
        }

        elapse = when_wall(n, elapse);
        if (elapse == 0)
                return 0;

        if (m->wall_message_timeout_source) {
                r = sd_event_source_set_time(m->wall_message_timeout_source, n + elapse);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_time() failed. %m");

                r = sd_event_source_set_enabled(m->wall_message_timeout_source, SD_EVENT_ONESHOT);
                if (r < 0)
                        return log_error_errno(r, "sd_event_source_set_enabled() failed. %m");
        } else {
                r = sd_event_add_time(m->event, &m->wall_message_timeout_source,
                                      CLOCK_REALTIME, n + elapse, 0, wall_message_timeout_handler, m);
                if (r < 0)
                        return log_error_errno(r, "sd_event_add_time() failed. %m");
        }

        return 0;
}
