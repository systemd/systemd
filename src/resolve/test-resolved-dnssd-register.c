/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <stdio.h>

#include "sd-bus.h"

#include "bus-error.h"
#include "log.h"
#include "main-func.h"

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *call = NULL, *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        const char *path;
        sigset_t ss;
        int r, sig;

        if (argc != 3)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected service ID and instance name.");

        assert_se(sigemptyset(&ss) >= 0);
        assert_se(sigaddset(&ss, SIGTERM) >= 0);
        assert_se(sigaddset(&ss, SIGINT) >= 0);
        assert_se(sigaddset(&ss, SIGUSR1) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &ss, NULL) >= 0);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_message_new_method_call(
                        bus,
                        &call,
                        "org.freedesktop.resolve1",
                        "/org/freedesktop/resolve1",
                        "org.freedesktop.resolve1.Manager",
                        "RegisterService");
        if (r < 0)
                return log_error_errno(r, "Failed to allocate RegisterService call: %m");

        r = sd_bus_message_append(call, "sssqqq", argv[1], argv[2], "_owner-test._tcp", 12345, 0, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to append service data: %m");

        r = sd_bus_message_open_container(call, SD_BUS_TYPE_ARRAY, "a{say}");
        if (r < 0)
                return log_error_errno(r, "Failed to open TXT array: %m");

        r = sd_bus_message_close_container(call);
        if (r < 0)
                return log_error_errno(r, "Failed to close TXT array: %m");

        r = sd_bus_call(bus, call, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to register service: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return log_error_errno(r, "Failed to read service path: %m");

        printf("%s\n", path);
        fflush(stdout);

        assert_se(sigwait(&ss, &sig) == 0);

        if (sig == SIGUSR1) {
                r = sd_bus_call_method(
                                bus,
                                "org.freedesktop.resolve1",
                                path,
                                "org.freedesktop.resolve1.DnssdService",
                                "Unregister",
                                &error,
                                NULL,
                                NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to unregister service: %s", bus_error_message(&error, r));
        }

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
