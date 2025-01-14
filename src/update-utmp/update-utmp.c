/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "sd-bus.h"

#include "audit-util.h"
#include "alloc-util.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "format-util.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "process-util.h"
#include "random-util.h"
#include "special.h"
#include "stdio-util.h"
#include "strv.h"
#include "unit-name.h"
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

#define MAX_ATTEMPTS 64u

static int get_current_runlevel(Context *c) {
        static const struct {
                const int runlevel;
                const char *special;
        } table[] = {
                /* The first target of this list that is active or has a job scheduled wins. We prefer
                 * runlevels 5 and 3 here over the others, since these are the main runlevels used on Fedora.
                 * It might make sense to change the order on some distributions. */
                { '5', SPECIAL_GRAPHICAL_TARGET  },
                { '3', SPECIAL_MULTI_USER_TARGET },
                { '1', SPECIAL_RESCUE_TARGET     },
        };
        int r;

        assert(c);

        for (unsigned n_attempts = 0;;) {
                if (n_attempts++ > 0) {
                        /* systemd might have dropped off momentarily, let's not make this an error,
                        * and wait some random time. Let's pick a random time in the range 100ms…2000ms,
                        * linearly scaled by the number of failed attempts. */
                        c->bus = sd_bus_flush_close_unref(c->bus);

                        usec_t usec =
                                UINT64_C(100) * USEC_PER_MSEC +
                                random_u64_range(UINT64_C(1900) * USEC_PER_MSEC * n_attempts / MAX_ATTEMPTS);
                        (void) usleep_safe(usec);
                }

                if (!c->bus) {
                        r = bus_connect_system_systemd(&c->bus);
                        if (r == -ECONNREFUSED && n_attempts < 64) {
                                log_debug_errno(r, "Failed to %s to system bus, retrying after a slight delay: %m",
                                                n_attempts <= 1 ? "connect" : "reconnect");
                                continue;
                        }
                        if (r < 0)
                                return log_error_errno(r, "Failed to reconnect to system bus: %m");
                }

                FOREACH_ELEMENT(e, table) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                        _cleanup_free_ char *state = NULL, *path = NULL;

                        path = unit_dbus_path_from_name(e->special);
                        if (!path)
                                return log_oom();

                        r = sd_bus_get_property_string(
                                        c->bus,
                                        "org.freedesktop.systemd1",
                                        path,
                                        "org.freedesktop.systemd1.Unit",
                                        "ActiveState",
                                        &error,
                                        &state);
                        if ((r == -ENOTCONN ||
                             sd_bus_error_has_names(&error,
                                                    SD_BUS_ERROR_NO_REPLY,
                                                    SD_BUS_ERROR_DISCONNECTED)) &&
                            n_attempts < MAX_ATTEMPTS) {
                                log_debug_errno(r, "Failed to get state of %s, retrying after a slight delay: %s",
                                                e->special, bus_error_message(&error, r));
                                break;
                        }
                        if (r < 0)
                                return log_warning_errno(r, "Failed to get state of %s: %s", e->special, bus_error_message(&error, r));

                        if (STR_IN_SET(state, "active", "reloading"))
                                return e->runlevel;
                }
                if (r >= 0)
                        return 0;
        }
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

static int on_runlevel(int argc, char *argv[], void *userdata) {
        Context *c = ASSERT_PTR(userdata);
        int r, q = 0, previous, runlevel;

        /* We finished changing runlevel, so let's write the utmp record and send the audit msg. */

        /* First, get last runlevel */
        r = utmp_get_runlevel(&previous, NULL);
        if (r < 0) {
                if (!IN_SET(r, -ESRCH, -ENOENT))
                        return log_error_errno(r, "Failed to get the last runlevel from utmp: %m");

                previous = 0;
        }

        /* Secondly, get new runlevel */
        runlevel = get_current_runlevel(c);
        if (runlevel < 0)
                return runlevel;
        if (runlevel == 0) {
                log_warning("Failed to get the current runlevel, utmp update skipped.");
                return 0;
        }

        if (previous == runlevel)
                return 0;

#if HAVE_AUDIT
        if (c->audit_fd >= 0) {
                char s[STRLEN("old-level=_ new-level=_") + 1];

                xsprintf(s, "old-level=%c new-level=%c",
                         previous > 0 ? previous : 'N',
                         runlevel);

                if (audit_log_user_comm_message(c->audit_fd, AUDIT_SYSTEM_RUNLEVEL, s,
                                                "systemd-update-utmp", NULL, NULL, NULL, 1) < 0 && errno != EPERM)
                        q = log_error_errno(errno, "Failed to send audit message: %m");
        }
#endif

        r = utmp_put_runlevel(runlevel, previous);
        if (r < 0 && !IN_SET(r, -ESRCH, -ENOENT))
                return log_error_errno(r, "Failed to write utmp record: %m");

        return q;
}

static int run(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "reboot",   1, 1, 0, on_reboot   },
                { "shutdown", 1, 1, 0, on_shutdown },
                { "runlevel", 1, 1, 0, on_runlevel },
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
