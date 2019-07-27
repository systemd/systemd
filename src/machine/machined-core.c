/* SPDX-License-Identifier: LGPL-2.1+ */

#include "machined.h"
#include "nscd-flush.h"
#include "strv.h"

static int on_nscd_cache_flush_event(sd_event_source *s, void *userdata) {
        /* Let's ask glibc's nscd daemon to flush its caches. We request this for the three database machines may show
         * up in: the hosts database (for resolvable machine names) and the user and group databases (for the user ns
         * ranges). */

        (void) nscd_flush_cache(STRV_MAKE("passwd", "group", "hosts"));
        return 0;
}

int manager_enqueue_nscd_cache_flush(Manager *m) {
        int r;

        assert(m);

        if (!m->nscd_cache_flush_event) {
                r = sd_event_add_defer(m->event, &m->nscd_cache_flush_event, on_nscd_cache_flush_event, m);
                if (r < 0)
                        return log_error_errno(r, "Failed to allocate NSCD cache flush event: %m");

                sd_event_source_set_description(m->nscd_cache_flush_event, "nscd-cache-flush");
        }

        r = sd_event_source_set_enabled(m->nscd_cache_flush_event, SD_EVENT_ONESHOT);
        if (r < 0) {
                m->nscd_cache_flush_event = sd_event_source_unref(m->nscd_cache_flush_event);
                return log_error_errno(r, "Failed to enable NSCD cache flush event: %m");
        }

        return 0;
}
