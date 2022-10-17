/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "analyze-dump.h"
#include "analyze.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "copy.h"

static int dump_fallback(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *text;
        int r;

        assert(bus);

        r = bus_call_method(bus, bus_systemd_mgr, "Dump", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to call Dump: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        fputs(text, stdout);
        return 0;
}

static int dump_fd_reply(sd_bus_message *message) {
        int fd, r;

        r = sd_bus_message_read(message, "h", &fd);
        if (r < 0)
                return bus_log_parse_error(r);

        fflush(stdout);
        r = copy_bytes(fd, STDOUT_FILENO, UINT64_MAX, 0);
        if (r < 0)
                return r;

        return 1;  /* Success */
}

static int dump(sd_bus *bus) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int r;

        r = bus_call_method(bus, bus_systemd_mgr, "DumpByFileDescriptor", &error, &reply, NULL);
        if (IN_SET(r, -EACCES, -EBADR))
                return 0;  /* Fall back to non-fd method. We need to do this even if the bus supports sending
                            * fds to cater to very old managers which didn't have the fd-based method. */
        if (r < 0)
                return log_error_errno(r, "Failed to call DumpByFileDescriptor: %s",
                                       bus_error_message(&error, r));

        return dump_fd_reply(reply);
}

static int dump_patterns_fallback(sd_bus *bus, char **patterns) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        const char *text;
        int r;

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "DumpUnitsMatchingPatterns");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, patterns);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to call DumpUnitsMatchingPatterns: %s",
                                       bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        fputs(text, stdout);
        return 0;
}

static int dump_patterns(sd_bus *bus, char **patterns) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL, *m = NULL;
        int r;

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "DumpUnitsMatchingPatternsByFileDescriptor");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_strv(m, patterns);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0)
                return log_error_errno(r, "Failed to call DumpUnitsMatchingPatternsByFileDescriptor: %s",
                                       bus_error_message(&error, r));

        return dump_fd_reply(reply);
}

static int mangle_patterns(char **args, char ***ret) {
        _cleanup_strv_free_ char **mangled = NULL;
        int r;

        STRV_FOREACH(arg, args) {
                char *t;

                r = unit_name_mangle_with_suffix(*arg, NULL, UNIT_NAME_MANGLE_GLOB, ".service", &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to mangle name '%s': %m", *arg);

                r = strv_consume(&mangled, t);
                if (r < 0)
                        return log_oom();
        }

        if (strv_isempty(mangled))
                mangled = strv_free(mangled);

        *ret = TAKE_PTR(mangled);
        return 0;
}

int verb_dump(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_strv_free_ char **patterns = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        pager_open(arg_pager_flags);

        r = mangle_patterns(strv_skip(argv, 1), &patterns);
        if (r < 0)
                return r;

        r = sd_bus_can_send(bus, SD_BUS_TYPE_UNIX_FD);
        if (r < 0)
                return log_error_errno(r, "Unable to determine if bus connection supports fd passing: %m");
        if (r > 0)
                r = patterns ? dump_patterns(bus, patterns) : dump(bus);
        if (r == 0) /* wasn't supported */
                r = patterns ? dump_patterns_fallback(bus, patterns) : dump_fallback(bus);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
