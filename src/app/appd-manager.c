/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "alloc-util.h"
#include "appd-instance.h"
#include "appd-instance-varlink.h"
#include "appd-manager.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "errno-util.h"
#include "hash-funcs.h"
#include "hashmap.h"
#include "log.h"
#include "main-func.h"

int manager_new(Manager **ret) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        assert(ret);

        m = new0(Manager, 1);
        if (!m)
                return -ENOMEM;

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_full_errno(ERRNO_IS_NOT_SUPPORTED(r) || ERRNO_IS_PRIVILEGE(r) || r == -EHOSTDOWN ? LOG_DEBUG : LOG_NOTICE, r,
                               "Unable to create memory pressure event source, ignoring: %m");

        (void) sd_event_set_watchdog(m->event, true);

        *ret = TAKE_PTR(m);
        return 0;
}

int manager_startup(Manager *m) {
        int r;

        assert(m);

        r = manager_instance_varlink_init(m);
        if (r < 0)
                return r;

        return 0;
}

Manager *manager_free(Manager *m) {
        if (!m)
                return NULL;

        manager_instance_varlink_done(m);

        m->instances = hashmap_free(m->instances);
        m->event = sd_event_unref(m->event);

        return mfree(m);
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_freep) Manager *m = NULL;
        int r;

        log_setup();

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Could not create manager: %m");

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to start up manager: %m");

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop = NULL;
        notify_stop = notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
