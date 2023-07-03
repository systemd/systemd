/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl.h"
#include "systemctl-util.h"
#include "systemctl-whoami.h"
#include "parse-util.h"

static int lookup_pid(sd_bus *bus, pid_t pid) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *unit = NULL;
        const char *path;
        int r;

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPID", &error, &reply, "u", (uint32_t) pid);
        if (r < 0)
                return log_error_errno(r, "Failed to get unit for ourselves: %s", bus_error_message(&error, r));

        r = sd_bus_message_read(reply, "o", &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = unit_name_from_dbus_path(path, &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to extract unit name from D-Bus object path '%s': %m", path);

        printf("%s\n", unit);
        return 0;
}

int verb_whoami(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        char **pids = strv_skip(argv, 1);

        if (strv_isempty(pids)) {

                if (arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE), "Refusing to look up local PID on remote host.");

                return lookup_pid(bus, 0);
        } else {
                int ret = 0;

                STRV_FOREACH(p, pids) {
                        pid_t pid;

                        r = parse_pid(*p, &pid);
                        if (r < 0) {
                                log_error_errno(r, "Failed to parse PID: %s", *p);
                                if (ret >= 0)
                                        ret = r;
                                continue;
                        }

                        r = lookup_pid(bus, pid);
                        if (r < 0 && ret >= 0)
                                ret = r;
                }

                return ret;
        }
}
