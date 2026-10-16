/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "counters-file.h"
#include "journald-counters.h"
#include "journald-manager.h"
#include "log.h"
#include "path-util.h"

int manager_map_counters(Manager *m) {
        int r;

        assert(m);
        assert(!m->counters);

        _cleanup_free_ char *fn = path_join(m->runtime_directory, "counters");
        if (!fn)
                return log_oom();

        r = counters_file_map(fn, sizeof(JournalCounters), JOURNAL_COUNTERS_VERSION, (void**) &m->counters);
        if (r < 0)
                return log_warning_errno(r, "Failed to map message counters file '%s', ignoring: %m", fn);

        return 0;
}

void manager_count_message(Manager *m, JournalTransport t, int priority) {
        assert(m);
        assert(t >= 0 && t < _JOURNAL_TRANSPORT_MAX);

        if (!m->counters)
                return;

        m->counters->n_priority[LOG_PRI(priority)]++;
        m->counters->n_transport[t]++;
}
