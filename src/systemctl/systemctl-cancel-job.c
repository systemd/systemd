/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "parse-util.h"
#include "systemctl-cancel-job.h"
#include "systemctl-trivial-method.h"
#include "systemctl-util.h"
#include "systemctl.h"

int verb_cancel(int argc, char *argv[], void *userdata) {
        sd_bus *bus;
        int r;

        if (argc <= 1) /* Shortcut to trivial_method() if no argument is given */
                return verb_trivial_method(argc, argv, userdata);

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        STRV_FOREACH(name, strv_skip(argv, 1)) {
                _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
                uint32_t id;
                int q;

                q = safe_atou32(*name, &id);
                if (q < 0)
                        return log_error_errno(q, "Failed to parse job id \"%s\": %m", *name);

                q = bus_call_method(bus, bus_systemd_mgr, "CancelJob", &error, NULL, "u", id);
                if (q < 0) {
                        log_error_errno(q, "Failed to cancel job %"PRIu32": %s", id, bus_error_message(&error, q));
                        if (r == 0)
                                r = q;
                }
        }

        return r;
}
