/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-common-errors.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "format-util.h"
#include "parse-util.h"
#include "pidref.h"
#include "process-util.h"
#include "systemctl.h"
#include "systemctl-util.h"
#include "systemctl-whoami.h"

static int lookup_pid_fallback(sd_bus *bus, const PidRef *pid) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *unit = NULL;
        const char *path;
        int r;

        assert(bus);
        assert(pidref_is_set(pid));

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPID", &error, &reply, "u", (uint32_t) pid->pid);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_UNIT_FOR_PID))
                        return log_error_errno(r, "%s", bus_error_message(&error, r));

                return log_error_errno(r,
                                       "Failed to get unit that PID " PID_FMT " belongs to: %s",
                                       pid->pid, bus_error_message(&error, r));
        }

        r = sd_bus_message_read_basic(reply, 's', &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = unit_name_from_dbus_path(path, &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to extract unit name from D-Bus object path '%s': %m", path);

        r = pidref_verify(pid);
        if (r < 0)
                return log_error_errno(r, "Failed to verify our reference to PID " PID_FMT ": %m", pid->pid);

        puts(unit);
        return 0;
}

static int lookup_pid(sd_bus *bus, const char *pidstr) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        const char *unit;
        int r;

        assert(bus);

        if (pidstr) {
                r = pidref_set_pidstr(&pid, pidstr);
                if (r < 0)
                        return log_error_errno(r,
                                               r == -ESRCH ?
                                               "PID %s doesn't exist or is already gone." :
                                               "Failed to create reference to PID %s: %m",
                                               pidstr);
        } else {
                r = pidref_set_pid(&pid, 0);
                if (r < 0) {
                        assert(r != -ESRCH);
                        return log_error_errno(r,
                                               "Failed to create reference to our own PID " PID_FMT ": %m",
                                               getpid_cached());
                }
        }

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPIDFD", &error, &reply, "h", pid.fd);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                        return lookup_pid_fallback(bus, &pid);

                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_UNIT_FOR_PID, BUS_ERROR_NO_SUCH_PROCESS))
                        return log_error_errno(r, "%s", bus_error_message(&error, r));

                return log_error_errno(r,
                                       "Failed to get unit that PID " PID_FMT " belongs to: %s",
                                       pid.pid, bus_error_message(&error, r));
        }

        r = sd_bus_message_read(reply, "os", NULL, &unit);
        if (r < 0)
                return bus_log_parse_error(r);

        puts(unit);
        return 0;
}

int verb_whoami(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        if (argc <= 1) {
                if (arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE), "Refusing to look up local PID on remote host.");

                return lookup_pid(bus, /* pidstr = */ NULL);
        }

        r = 0;

        STRV_FOREACH(pid, strv_skip(argv, 1))
                RET_GATHER(r, lookup_pid(bus, *pid));

        return r;
}
