/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <sys/types.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-log-control-api.h"
#include "bus-polkit.h"
#include "common-signal.h"
#include "constants.h"
#include "daemon-util.h"
#include "main-func.h"
#include "portabled-bus.h"
#include "portabled-image-bus.h"
#include "portabled.h"
#include "process-util.h"
#include "service-util.h"
#include "signal-util.h"

static Manager* manager_unref(Manager *m);
DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_unref);

static int manager_new(Manager **ret) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        assert(ret);

        m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .runtime_scope = RUNTIME_SCOPE_SYSTEM,
        };

        r = sd_event_default(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret_event_source= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, NULL, NULL, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed allocate memory pressure event source, ignoring: %m");

        (void) sd_event_set_watchdog(m->event, true);

        *ret = TAKE_PTR(m);
        return 0;
}

static Manager* manager_unref(Manager *m) {
        assert(m);

        hashmap_free(m->image_cache);

        sd_event_source_unref(m->image_cache_defer_event);

        hashmap_free(m->polkit_registry);

        sd_bus_flush_close_unref(m->bus);
        sd_event_unref(m->event);

        return mfree(m);
}

static int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(!m->bus);

        r = sd_bus_default_system(&m->bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->bus, NULL, "org.freedesktop.portable1", 0, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        (void) sd_bus_set_exit_on_disconnect(m->bus, true);

        return 0;
}

static int manager_startup(Manager *m) {
        int r;

        assert(m);

        r = manager_connect_bus(m);
        if (r < 0)
                return r;

        return 0;
}

static bool check_idle(void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        return !m->operations &&
                hashmap_isempty(m->polkit_registry);
}

static int run(int argc, char *argv[]) {
        _cleanup_(manager_unrefp) Manager *m = NULL;
        int r;

        log_setup();

        r = service_parse_argv("systemd-portabled.service",
                               "Manage registrations of portable images.",
                               BUS_IMPLEMENTATIONS(&manager_object,
                                                   &log_control_object),
                               argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "This program takes no arguments.");

        assert_se(sigprocmask_many(SIG_BLOCK, /* ret_old_mask= */ NULL, SIGCHLD) >= 0);

        r = manager_new(&m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate manager object: %m");

        r = manager_startup(m);
        if (r < 0)
                return log_error_errno(r, "Failed to fully start up daemon: %m");

        r = sd_notify(false, NOTIFY_READY);
        if (r < 0)
                log_warning_errno(r, "Failed to send readiness notification, ignoring: %m");

        r = bus_event_loop_with_idle(
                        m->event,
                        m->bus,
                        "org.freedesktop.portable1",
                        DEFAULT_EXIT_USEC,
                        check_idle, m);
        if (r < 0)
                return log_error_errno(r, "Failed to run main loop: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
