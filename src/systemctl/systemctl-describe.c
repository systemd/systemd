/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "systemctl.h"
#include "systemctl-util.h"
#include "systemctl-describe.h"

int verb_describe(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_error_free) sd_bus_error e = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        sd_bus *bus;
        const char *text;
        int r;

        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        r = bus_call_method(bus, bus_systemd_mgr, "Describe", &e, &reply, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to get description: %m");

        r = sd_bus_message_read(reply, "s", &text);
        if (r < 0)
                return bus_log_parse_error(r);

        r = json_parse(text, 0, &v, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse JSON: %m");

        (void) json_variant_dump(v, JSON_FORMAT_PRETTY|JSON_FORMAT_COLOR_AUTO, NULL, NULL);
        return 0;
}
