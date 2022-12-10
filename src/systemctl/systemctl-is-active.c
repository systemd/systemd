/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error.h"
#include "bus-locator.h"
#include "pretty-print.h"
#include "syslog-util.h"
#include "systemctl-is-active.h"
#include "systemctl-sysv-compat.h"
#include "systemctl-util.h"
#include "systemctl.h"

static int check_unit_generic(int code, const UnitActiveState good_states[], int nb_states, char **args) {
        _cleanup_strv_free_ char **names = NULL;
        UnitActiveState active_state;
        sd_bus *bus;
        bool not_found = true, ok = false;
        int r;

        r = acquire_bus(BUS_MANAGER, &bus);
        if (r < 0)
                return r;

        r = expand_unit_names(bus, args, NULL, &names, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to expand names: %m");

        STRV_FOREACH(name, names) {
                _cleanup_free_ char *load_state = NULL;

                r = get_state_one_unit(bus, *name, &active_state);
                if (r < 0)
                        return r;

                r = unit_load_state(bus, *name, &load_state);
                if (r < 0)
                        return r;

                if (!arg_quiet)
                        puts(unit_active_state_to_string(active_state));

                for (int i = 0; i < nb_states; ++i)
                        if (good_states[i] == active_state) {
                                ok = true;
                                break;
                        }

                if (!streq(load_state, "not-found"))
                        not_found = false;
        }

        /* We use LSB code 4 ("program or service status is unknown")
         * when the corresponding unit file doesn't exist. */
        return ok ? EXIT_SUCCESS : not_found ? EXIT_PROGRAM_OR_SERVICES_STATUS_UNKNOWN : code;
}

int verb_is_active(int argc, char *argv[], void *userdata) {
        static const UnitActiveState states[] = {
                UNIT_ACTIVE,
                UNIT_RELOADING,
        };

        /* According to LSB: 3, "program is not running" */
        return check_unit_generic(EXIT_PROGRAM_NOT_RUNNING, states, ELEMENTSOF(states), strv_skip(argv, 1));
}

int verb_is_failed(int argc, char *argv[], void *userdata) {
        static const UnitActiveState states[] = {
                UNIT_FAILED,
        };

        return check_unit_generic(EXIT_PROGRAM_DEAD_AND_PID_EXISTS, states, ELEMENTSOF(states), strv_skip(argv, 1));
}
