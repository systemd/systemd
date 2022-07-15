/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "machined.h"
#include "nscd-flush.h"
#include "strv.h"
#include "user-util.h"

#if ENABLE_NSCD
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
#endif

int manager_find_machine_for_uid(Manager *m, uid_t uid, Machine **ret_machine, uid_t *ret_internal_uid) {
        Machine *machine;
        int r;

        assert(m);
        assert(uid_is_valid(uid));

        /* Finds the machine for the specified host UID and returns it along with the UID translated into the
         * internal UID inside the machine */

        HASHMAP_FOREACH(machine, m->machines) {
                uid_t converted;

                r = machine_owns_uid(machine, uid, &converted);
                if (r < 0)
                        return r;
                if (r) {
                        if (ret_machine)
                                *ret_machine = machine;

                        if (ret_internal_uid)
                                *ret_internal_uid = converted;

                        return true;
                }
        }

        if (ret_machine)
                *ret_machine = NULL;
        if (ret_internal_uid)
                *ret_internal_uid = UID_INVALID;

        return false;
}

int manager_find_machine_for_gid(Manager *m, gid_t gid, Machine **ret_machine, gid_t *ret_internal_gid) {
        Machine *machine;
        int r;

        assert(m);
        assert(gid_is_valid(gid));

        HASHMAP_FOREACH(machine, m->machines) {
                gid_t converted;

                r = machine_owns_gid(machine, gid, &converted);
                if (r < 0)
                        return r;
                if (r) {
                        if (ret_machine)
                                *ret_machine = machine;

                        if (ret_internal_gid)
                                *ret_internal_gid = converted;

                        return true;
                }
        }

        if (ret_machine)
                *ret_machine = NULL;
        if (ret_internal_gid)
                *ret_internal_gid = GID_INVALID;

        return false;
}
