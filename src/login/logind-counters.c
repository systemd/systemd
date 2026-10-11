/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "counters-file.h"
#include "log.h"
#include "logind.h"
#include "logind-counters.h"
#include "logind-session.h"

int manager_map_counters(Manager *m) {
        int r;

        assert(m);
        assert(!m->counters);

        r = counters_file_map(LOGIN_COUNTERS_PATH, sizeof(LoginCounters), LOGIN_COUNTERS_VERSION, (void**) &m->counters);
        if (r < 0)
                return log_warning_errno(r, "Failed to map counters file '%s', ignoring: %m", LOGIN_COUNTERS_PATH);

        return 0;
}

void session_count_started(Session *s) {
        assert(s);
        assert(s->manager);
        assert(s->class >= 0 && s->class < _SESSION_CLASS_MAX);

        if (!s->manager->counters)
                return;

        s->manager->counters->n_sessions_started[s->class]++;
}
