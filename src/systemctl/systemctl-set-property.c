/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-set-property.h"
#include "systemctl-util.h"
#include "systemctl.h"

int set_property(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_free_ char *n = NULL;
        UnitType t;
        sd_bus *bus;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties");
        if (r < 0)
                return bus_log_create_error(r);

        r = unit_name_mangle(argv[1], arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN, &n);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        t = unit_name_to_type(n);
        if (t < 0)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid unit type: %s", n);

        r = sd_bus_message_append(m, "sb", n, arg_runtime);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = bus_append_unit_property_assignment_many(m, t, strv_skip(argv, 2));
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set unit properties on %s: %s", n, bus_error_message(&error, r));

        return 0;
}
