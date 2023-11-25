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

static int get_unit_by_pid(sd_bus *bus, pid_t pid, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_free_ char *unit = NULL;
        const char *path;
        int r;

        assert(bus);
        assert(pid >= 0); /* 0 is accepted by GetUnitByPID for querying our own process. */
        assert(ret);

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPID", &error, &reply, "u", (uint32_t) pid);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, BUS_ERROR_NO_UNIT_FOR_PID))
                        return log_error_errno(r, "%s", bus_error_message(&error, r));

                return log_error_errno(r,
                                       "Failed to get unit that PID " PID_FMT " belongs to: %s",
                                       pid > 0 ? pid : getpid_cached(),
                                       bus_error_message(&error, r));
        }

        r = sd_bus_message_read_basic(reply, 'o', &path);
        if (r < 0)
                return bus_log_parse_error(r);

        r = unit_name_from_dbus_path(path, &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to extract unit name from D-Bus object path '%s': %m", path);

        *ret = TAKE_PTR(unit);
        return 0;
}

static int lookup_pidfd(sd_bus *bus, const PidRef *pid, char **ret) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        const char *unit;
        int r;

        assert(bus);
        assert(pidref_is_set(pid));
        assert(ret);

        if (pid->fd < 0)
                return -EOPNOTSUPP;

        r = bus_call_method(bus, bus_systemd_mgr, "GetUnitByPIDFD", &error, &reply, "h", pid->fd);
        if (r < 0) {
                if (sd_bus_error_has_name(&error, SD_BUS_ERROR_UNKNOWN_METHOD))
                        return -EOPNOTSUPP;

                if (sd_bus_error_has_names(&error, BUS_ERROR_NO_UNIT_FOR_PID, BUS_ERROR_NO_SUCH_PROCESS))
                        return log_error_errno(r, "%s", bus_error_message(&error, r));

                return log_error_errno(r,
                                       "Failed to get unit that PID " PID_FMT " belongs to: %s",
                                       pid->pid, bus_error_message(&error, r));
        }

        r = sd_bus_message_read(reply, "os", NULL, &unit);
        if (r < 0)
                return bus_log_parse_error(r);

        char *u = strdup(unit);
        if (!u)
                return log_oom();

        *ret = TAKE_PTR(u);

        return 0;
}

static int lookup_pid(sd_bus *bus, const char *pidstr) {
        _cleanup_free_ char *unit = NULL;
        int r;

        assert(bus);
        assert(pidstr);

        if (arg_transport == BUS_TRANSPORT_LOCAL) {
                static bool use_pidfd = true;
                _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;

                r = pidref_set_pidstr(&pid, pidstr);
                if (r < 0)
                        return log_error_errno(r,
                                               r == -ESRCH ?
                                               "PID %s doesn't exist or is already gone." :
                                               "Failed to create reference to PID %s: %m",
                                               pidstr);

                if (use_pidfd) {
                        r = lookup_pidfd(bus, &pid, &unit);
                        if (r == -EOPNOTSUPP) {
                                use_pidfd = false;
                                log_debug_errno(r, "Unable to look up process using pidfd, ignoring.");
                        } else if (r < 0)
                                return r;
                }

                if (!use_pidfd) {
                        assert(!unit);

                        r = get_unit_by_pid(bus, pid.pid, &unit);
                        if (r < 0)
                                return r;

                        r = pidref_verify(&pid);
                        if (r < 0)
                                return log_error_errno(r,
                                                       "Failed to verify our reference to PID " PID_FMT ": %m",
                                                       pid.pid);
                }
        } else {
                pid_t pid;

                r = parse_pid(pidstr, &pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse PID %s: %m", pidstr);

                r = get_unit_by_pid(bus, pid, &unit);
                if (r < 0)
                        return r;
        }

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
                _cleanup_free_ char *unit = NULL;

                if (arg_transport != BUS_TRANSPORT_LOCAL)
                        return log_error_errno(SYNTHETIC_ERRNO(EREMOTE), "Refusing to look up our local PID on remote host.");

                /* Our own process can never go away while querying, hence no need to open pidfd. */

                r = get_unit_by_pid(bus, 0, &unit);
                if (r < 0)
                        return r;

                puts(unit);
                return 0;
        }

        r = 0;

        STRV_FOREACH(pid, strv_skip(argv, 1))
                RET_GATHER(r, lookup_pid(bus, *pid));

        return r;
}
