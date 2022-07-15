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
        const char *text = NULL;
        int r;

        assert(bus);

        r = bus_call_method(bus, bus_systemd_mgr, "Dump", &error, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to issue method call Dump: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        fputs(text, stdout);
        return 0;
}

int verb_dump(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int fd = -1;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        pager_open(arg_pager_flags);

        if (!sd_bus_can_send(bus, SD_BUS_TYPE_UNIX_FD))
                return dump_fallback(bus);

        r = bus_call_method(bus, bus_systemd_mgr, "DumpByFileDescriptor", &error, &reply, NULL);
        if (r < 0) {
                /* fall back to Dump if DumpByFileDescriptor is not supported */
                if (!IN_SET(r, -EACCES, -EBADR))
                        return log_error_errno(r, "Failed to issue method call DumpByFileDescriptor: %s",
                                               bus_error_message(&error, r));

                return dump_fallback(bus);
        }

        r = sd_bus_message_read(reply, "h", &fd);
        if (r < 0)
                return bus_log_parse_error(r);

        fflush(stdout);
        r = copy_bytes(fd, STDOUT_FILENO, UINT64_MAX, 0);
        if (r < 0)
                return r;

        return EXIT_SUCCESS;
}
