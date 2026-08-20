/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <signal.h>
#include <stdio.h>
#include <sys/socket.h>

#include "sd-bus.h"
#include "bus-error.h"
#include "log.h"
#include "main-func.h"
#include "resolved-def.h"
#include "string-util.h"

#define BROWSER_INTERFACE "org.freedesktop.resolve1.DnssdServiceBrowser"

typedef struct BrowserUpdates {
        bool added;
        bool removed;
} BrowserUpdates;

static int on_services_changed(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        BrowserUpdates *updates = ASSERT_PTR(userdata);
        int r;

        r = sd_bus_message_enter_container(message, 'a', "(sisssi)");
        if (r < 0)
                return r;

        for (;;) {
                const char *update, *name, *type, *domain;
                int family, ifindex;

                r = sd_bus_message_read(message, "(sisssi)", &update, &family, &name, &type, &domain, &ifindex);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!IN_SET(family, AF_INET, AF_INET6) || ifindex <= 0)
                        return -EBADMSG;

                if (streq(name, "Owner Browser") && streq(type, "_owner-test._tcp") &&
                    streq(domain, "local")) {
                        if (streq(update, "added"))
                                updates->added = true;
                        else if (streq(update, "removed"))
                                updates->removed = true;
                }
        }

        return sd_bus_message_exit_container(message);
}

static int run(int argc, char *argv[]) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        BrowserUpdates updates = {};
        bool added_reported = false, removed_reported = false;
        const char *path;
        uint64_t flags;
        sigset_t ss;
        int r;

        if (argc != 1)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Expected no arguments.");

        assert_se(sigemptyset(&ss) >= 0);
        assert_se(sigaddset(&ss, SIGTERM) >= 0);
        assert_se(sigaddset(&ss, SIGINT) >= 0);
        assert_se(sigaddset(&ss, SIGUSR1) >= 0);
        assert_se(sigprocmask(SIG_BLOCK, &ss, NULL) >= 0);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to system bus: %m");

        r = sd_bus_add_match(bus, &slot,
                             "type='signal',interface='" BROWSER_INTERFACE "',member='ServicesChanged'",
                             on_services_changed, &updates);
        if (r < 0)
                return log_error_errno(r, "Failed to install browser signal match: %m");

        r = sd_bus_call_method(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager", "BrowseServices", &error, &reply,
                               "ssit", "local", "_owner-test._tcp", 0, (uint64_t) SD_RESOLVED_MDNS);
        if (r < 0)
                return log_error_errno(r, "Failed to browse services: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "ot", &path, &flags);
        if (r < 0)
                return log_error_errno(r, "Failed to read browser path: %m");
        if (!FLAGS_SET(flags, SD_RESOLVED_MDNS))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "BrowseServices() did not return effective mDNS flags.");

        r = sd_bus_call_method(bus, "org.freedesktop.resolve1", "/org/freedesktop/resolve1",
                               "org.freedesktop.resolve1.Manager", "BrowseServices", &error, NULL,
                               "ssit", "local", "_owner-test._tcp", 0, (uint64_t) SD_RESOLVED_MDNS);
        if (r >= 0 || !sd_bus_error_has_name(&error, SD_BUS_ERROR_LIMITS_EXCEEDED))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "Second browser request did not fail with LimitsExceeded: %s",
                                       bus_error_message(&error, r));
        sd_bus_error_free(&error);

        printf("%s\n", path);
        fflush(stdout);

        for (;;) {
                struct timespec ts = {};
                int sig;

                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus messages: %m");

                if (updates.added && !added_reported) {
                        puts("updated");
                        fflush(stdout);
                        added_reported = true;
                }
                if (updates.removed && !removed_reported) {
                        puts("removed");
                        fflush(stdout);
                        removed_reported = true;
                }

                sig = sigtimedwait(&ss, NULL, &ts);
                if (sig == SIGUSR1) {
                        r = sd_bus_call_method(bus, "org.freedesktop.resolve1", path, BROWSER_INTERFACE,
                                               "Stop", &error, NULL, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to stop browser: %s", bus_error_message(&error, r));

                        r = sd_bus_call_method(bus, "org.freedesktop.resolve1", path, BROWSER_INTERFACE,
                                               "Stop", &error, NULL, NULL);
                        if (r >= 0 || !sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_OBJECT))
                                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                                       "Second Stop() did not fail with UnknownObject: %s",
                                                       bus_error_message(&error, r));
                        return 0;
                }
                if (sig == SIGTERM || sig == SIGINT)
                        return 0;

                if (r == 0) {
                        r = sd_bus_wait(bus, 100 * 1000);
                        if (r < 0)
                                return log_error_errno(r, "Failed to wait for bus messages: %m");
                }
        }
}

DEFINE_MAIN_FUNCTION(run);
