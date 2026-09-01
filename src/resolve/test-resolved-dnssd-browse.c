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
#include "strv.h"

#define BROWSER_INTERFACE "org.freedesktop.resolve1.DnssdServiceBrowser"
#define BROWSER_PATH "/org/freedesktop/resolve1/browser"
#define MANAGER_INTERFACE "org.freedesktop.resolve1.Manager"
#define RESOLVE_DESTINATION "org.freedesktop.resolve1"

static int browse_services(
                sd_bus *bus,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags,
                char **ret_path) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *path;
        uint64_t effective_flags;
        int r;

        r = sd_bus_call_method(bus, RESOLVE_DESTINATION, "/org/freedesktop/resolve1",
                               MANAGER_INTERFACE, "BrowseServices", &error, &reply,
                               "ssit", domain, type, ifindex, flags);
        if (r < 0)
                return log_error_errno(r, "Failed to browse services: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "ot", &path, &effective_flags);
        if (r < 0)
                return r;
        if (!FLAGS_SET(effective_flags, SD_RESOLVED_MDNS))
                return -ENOTRECOVERABLE;

        if (ret_path) {
                *ret_path = strdup(path);
                if (!*ret_path)
                        return -ENOMEM;
        }

        return 0;
}

static int assert_browse_error(
                sd_bus *bus,
                const char *domain,
                const char *type,
                int ifindex,
                uint64_t flags,
                const char *expected) {

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = sd_bus_call_method(bus, RESOLVE_DESTINATION, "/org/freedesktop/resolve1",
                               MANAGER_INTERFACE, "BrowseServices", &error, NULL,
                               "ssit", domain, type, ifindex, flags);
        if (r >= 0 || !sd_bus_error_has_name(&error, expected))
                return log_error_errno(SYNTHETIC_ERRNO(ENOTRECOVERABLE),
                                       "BrowseServices() did not fail with %s: %s",
                                       expected, bus_error_message(&error, r));

        return 0;
}

static int stop_browser(sd_bus *bus, const char *path) {
        return sd_bus_call_method(bus, RESOLVE_DESTINATION, path, BROWSER_INTERFACE, "Stop", NULL, NULL, NULL);
}

static int test_browse_validation(sd_bus *bus) {
        int r;

        r = assert_browse_error(bus, "local", "_http._tcp", -1, SD_RESOLVED_MDNS, SD_BUS_ERROR_INVALID_ARGS);
        if (r < 0)
                return r;
        r = assert_browse_error(bus, "local", "invalid", 0, SD_RESOLVED_MDNS, SD_BUS_ERROR_INVALID_ARGS);
        if (r < 0)
                return r;
        r = assert_browse_error(bus, "invalid..local", "_http._tcp", 0, SD_RESOLVED_MDNS,
                                SD_BUS_ERROR_INVALID_ARGS);
        if (r < 0)
                return r;
        r = assert_browse_error(bus, "local", "_http._tcp", 0, UINT64_MAX, SD_BUS_ERROR_INVALID_ARGS);
        if (r < 0)
                return r;

        return assert_browse_error(bus, "local", "_http._tcp", 0, SD_RESOLVED_DNS, SD_BUS_ERROR_NOT_SUPPORTED);
}

static int test_browse_limits(void) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *a = NULL, *b = NULL, *c = NULL;
        _cleanup_strv_free_ char **a_paths = NULL, **b_paths = NULL;
        int r;

        r = sd_bus_open_system(&a);
        if (r < 0)
                return r;
        r = sd_bus_open_system(&b);
        if (r < 0)
                return r;
        r = sd_bus_open_system(&c);
        if (r < 0)
                return r;

        for (unsigned i = 0; i < 16; i++) {
                _cleanup_free_ char *path = NULL;

                r = browse_services(a, "local", "_http._tcp", 0, SD_RESOLVED_MDNS, &path);
                if (r < 0)
                        return r;
                r = strv_consume(&a_paths, TAKE_PTR(path));
                if (r < 0)
                        return r;
        }
        r = assert_browse_error(a, "local", "_http._tcp", 0, SD_RESOLVED_MDNS, SD_BUS_ERROR_LIMITS_EXCEEDED);
        if (r < 0)
                return r;

        for (unsigned i = 0; i < 16; i++) {
                _cleanup_free_ char *path = NULL;

                r = browse_services(b, "local", "_http._tcp", 0, SD_RESOLVED_MDNS, &path);
                if (r < 0)
                        return r;
                r = strv_consume(&b_paths, TAKE_PTR(path));
                if (r < 0)
                        return r;
        }
        r = assert_browse_error(c, "local", "_http._tcp", 0, SD_RESOLVED_MDNS, SD_BUS_ERROR_LIMITS_EXCEEDED);
        if (r < 0)
                return r;

        STRV_FOREACH(path, a_paths)
                assert_se(stop_browser(a, *path) >= 0);
        STRV_FOREACH(path, b_paths)
                assert_se(stop_browser(b, *path) >= 0);

        return 0;
}

static int assert_owner_can_enumerate(sd_bus *bus, const char *path) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *name, *xml;
        int r;

        r = sd_bus_call_method(bus, RESOLVE_DESTINATION, BROWSER_PATH,
                               "org.freedesktop.DBus.Introspectable", "Introspect",
                               NULL, &reply, NULL);
        if (r < 0)
                return r;
        r = sd_bus_message_read(reply, "s", &xml);
        if (r < 0)
                return r;

        name = strrchr(path, '/');
        if (!name || !strstr(xml, name + 1))
                return -ENOTRECOVERABLE;

        return 0;
}

typedef struct BrowserUpdates {
        bool added;
        bool removed;
        bool bad;
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

                if (!IN_SET(family, AF_INET, AF_INET6) || ifindex <= 0) {
                        updates->bad = true;
                        continue;
                }

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
        _cleanup_(sd_bus_slot_unrefp) sd_bus_slot *slot = NULL;
        BrowserUpdates updates = {};
        bool added_reported = false, removed_reported = false;
        _cleanup_free_ char *path = NULL;
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

        r = test_browse_validation(bus);
        if (r < 0)
                return r;
        r = test_browse_limits();
        if (r < 0)
                return log_error_errno(r, "Failed to test browser limits: %m");

        r = sd_bus_add_match(bus, &slot,
                             "type='signal',interface='" BROWSER_INTERFACE "',member='ServicesChanged'",
                             on_services_changed, &updates);
        if (r < 0)
                return log_error_errno(r, "Failed to install browser signal match: %m");

        r = browse_services(bus, "local", "_owner-test._tcp", 0, SD_RESOLVED_MDNS, &path);
        if (r < 0)
                return r;
        r = assert_owner_can_enumerate(bus, path);
        if (r < 0)
                return log_error_errno(r, "Browser owner could not enumerate its object: %m");

        printf("%s\n", path);
        fflush(stdout);

        for (;;) {
                struct timespec ts = {};
                int sig;

                r = sd_bus_process(bus, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus messages: %m");
                if (updates.bad)
                        return log_error_errno(SYNTHETIC_ERRNO(EBADMSG), "Received malformed browser update.");

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
