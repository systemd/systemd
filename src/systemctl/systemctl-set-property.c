/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl-set-property.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int set_property_one(sd_bus *bus, const char *name, char **properties) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        r = bus_message_new_method_call(bus, &m, bus_systemd_mgr, "SetUnitProperties");
        if (r < 0)
                return bus_log_create_error(r);

        UnitType t = unit_name_to_type(name);
        if (t < 0)
                return log_error_errno(t, "Invalid unit type: %s", name);

        r = sd_bus_message_append(m, "sb", name, arg_runtime);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, "(sv)");
        if (r < 0)
                return bus_log_create_error(r);

        r = bus_append_unit_property_assignment_many(m, t, properties);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to set unit properties on %s: %s",
                                       name, bus_error_message(&error, r));

        return 0;
}

int set_property(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        _cleanup_strv_free_ char **names = NULL;
        char **name;
        int r, k;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = expand_unit_names(bus, STRV_MAKE(argv[1]), NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand '%s' into names: %m", argv[1]);

        r = 0;
        STRV_FOREACH(name, names) {
                k = set_property_one(bus, *name, strv_skip(argv, 2));
                if (k < 0 && r >= 0)
                        r = k;
        }
        return r;
}
