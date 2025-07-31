/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "libaudit-util.h"
#include "log.h"
#include "main-func.h"
#include "random-util.h"
#include "special.h"
#include "stdio-util.h"
#include "strv.h"
#include "time-util.h"
#include "unit-def.h"
#include "utmp-wtmp.h"
#include "verbs.h"

typedef struct Context {
        sd_bus *bus;
        int audit_fd;
} Context;

static void context_clear(Context *c) {
        assert(c);

        c->bus = sd_bus_flush_close_unref(c->bus);
        c->audit_fd = close_audit_fd(c->audit_fd);
}

static int get_startup_monotonic_time(Context *c, usec_t *ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(c);
        assert(ret);

        if (!c->bus) {
                r = bus_connect_system_systemd(&c->bus);
                if (r < 0)
                        return log_warning_errno(r, "Failed to get D-Bus connection, ignoring: %m");
        }

        r = bus_get_property_trivial(
                        c->bus,
                        bus_systemd_mgr,
                        "UserspaceTimestampMonotonic",
                        &error,
                        't', ret);
        if (r < 0)
                return log_warning_errno(r, "Failed to get timestamp, ignoring: %s", bus_error_message(&error, r));

        return 0;
}

static int on_reboot(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        usec_t t = 0, boottime;
        int r, q = 0;

        /* We finished start-up, so let's write the utmp record and send the audit msg. */

#if HAVE_AUDIT
        if (c->audit_fd >= 0)
                if (audit_log_user_comm_message(c->audit_fd, AUDIT_SYSTEM_BOOT, "", "systemd-update-utmp", NULL, NULL, NULL, 1) < 0 &&
                    errno != EPERM)
                        q = log_error_errno(errno, "Failed to send audit message: %m");
#endif

        /* If this call fails, then utmp_put_reboot() will fix to the current time. */
        (void) get_startup_monotonic_time(c, &t);
        boottime = map_clock_usec(t, CLOCK_MONOTONIC, CLOCK_REALTIME);
        /* We query the recorded monotonic time here (instead of the system clock CLOCK_REALTIME), even
         * though we actually want the system clock time. That's because there's a likely chance that the
         * system clock wasn't set right during early boot. By manually converting the monotonic clock to the
         * system clock here we can compensate for incorrectly set clocks during early boot. */

        r = utmp_put_reboot(boottime);
        if (r < 0)
                return log_error_errno(r, "Failed to write utmp record: %m");

        return q;
}

static int on_shutdown(int argc, char *argv[], void *userdata) {
        int r, q = 0;

        /* We started shut-down, so let's write the utmp record and send the audit msg. */

#if HAVE_AUDIT
        Context *c = ASSERT_PTR(userdata);

        if (c->audit_fd >= 0)
                if (audit_log_user_comm_message(c->audit_fd, AUDIT_SYSTEM_SHUTDOWN, "", "systemd-update-utmp", NULL, NULL, NULL, 1) < 0 &&
                    errno != EPERM)
                        q = log_error_errno(errno, "Failed to send audit message: %m");
#endif

        r = utmp_put_shutdown();
        if (r < 0)
                return log_error_errno(r, "Failed to write utmp record: %m");

        return q;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "reboot",   1, 1, 0, on_reboot   },
                { "shutdown", 1, 1, 0, on_shutdown },
                {}
        };

        _cleanup_(context_clear) Context c = {
                .audit_fd = -EBADF,
        };

        log_setup();

        umask(0022);

        c.audit_fd = open_audit_fd_or_warn();

        return dispatch_verb(argc, argv, verbs, &c);
}

DEFINE_MAIN_FUNCTION(run);
