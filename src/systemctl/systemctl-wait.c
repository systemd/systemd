/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>

#include "sd-daemon.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "bus-wait-for-units.h"
#include "fork-notify.h"
#include "log.h"
#include "output-mode.h"
#include "pidref.h"
#include "runtime-scope.h"
#include "string-util.h"
#include "systemctl.h"
#include "systemctl-util.h"
#include "systemctl-wait.h"
#include "unit-name.h"
#include "unit-result.h"

typedef struct WaitContext {
        UnitResult result;
        bool good;
} WaitContext;

static void wait_context_done(WaitContext *c) {
        assert(c);

        unit_result_done(&c->result);
}

static void wait_unit_callback(BusWaitForUnits *d, const char *unit, bool good, UnitResult *result, void *userdata) {
        WaitContext *c = ASSERT_PTR(userdata);

        c->good = good;

        if (result) {
                unit_result_done(&c->result);
                c->result = TAKE_STRUCT(*result);
        }
}

static void wait_ready_callback(BusWaitForUnits *d, void *userdata) {
        /* We are now subscribed to all relevant signals and know the current state of the unit, i.e. from
         * here on we won't miss any state change. If we are running as a Type=notify service, let the service
         * manager know, so that callers can synchronize on this. */
        (void) sd_notify(/* unset_environment= */ false, "READY=1");
}

int verb_wait(int argc, char *argv[], uintptr_t _data, void *userdata) {
        _cleanup_(bus_wait_for_units_freep) BusWaitForUnits *w = NULL;
        _cleanup_(wait_context_done) WaitContext c = {
                .result = UNIT_RESULT_INIT,
        };
        _cleanup_free_ char *name = NULL;
        sd_bus *bus;
        int r;

        if (arg_no_block)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--no-block may not be combined with 'wait', refusing.");

        r = unit_name_mangle_with_suffix(argv[1], /* operation= */ NULL, arg_quiet ? 0 : UNIT_NAME_MANGLE_WARN, ".service", &name);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle unit name: %m");

        if (unit_name_is_valid(name, UNIT_NAME_TEMPLATE))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Cannot wait for template unit %s.", name);

        /* We need the full bus for this, since we reference the unit with RefUnit(), so that it is not
         * released while we are waiting for it, and its final state remains queriable. */
        r = acquire_bus(BUS_FULL, &bus);
        if (r < 0)
                return r;

        polkit_agent_open_maybe();

        r = bus_wait_for_units_new(bus, &w);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate unit watch context: %m");

        r = bus_wait_for_units_add_unit(
                        w,
                        name,
                        BUS_WAIT_FOR_INACTIVE|BUS_WAIT_NO_JOB|BUS_WAIT_COLLECT_RESULT,
                        wait_unit_callback,
                        &c);
        if (r < 0)
                return log_error_errno(r, "Failed to watch unit %s: %m", name);

        bus_wait_for_units_set_ready_callback(w, wait_ready_callback, /* userdata= */ NULL);

        _cleanup_(fork_notify_terminate) PidRef journal_pid = PIDREF_NULL;
        if (arg_verbose)
                (void) journal_fork(arg_runtime_scope, STRV_MAKE(name), arg_output, &journal_pid);

        r = bus_wait_for_units_run(w);
        if (r < 0)
                return log_error_errno(r, "Failed to wait for unit %s: %m", name);

        /* Close the journal watch logic before we output the exit summary */
        fork_notify_terminate(&journal_pid);

        /* Send out READY=1 here. This might be redundant, because wait_ready_callback() already sent it
         * out. But this might also not be redundant, as we might have completed work before all signal
         * matches have been successfully installed. Since sending this out twice doesn't hurt, let's
         * generate it in both cases. */
        (void) sd_notify(/* unset_environment= */ false, "READY=1");

        if (!c.good)
                return log_error_errno(SYNTHETIC_ERRNO(EIO), "Failed to wait for unit %s to terminate.", name);

        /* A unit that does not exist is treated like one that already terminated successfully. */
        if (streq_ptr(c.result.load_state, "not-found")) {
                if (!arg_quiet)
                        printf("Unit %s does not exist, treating as terminated.\n", name);

                return EXIT_SUCCESS;
        }

        if (!arg_quiet)
                (void) unit_result_show(
                                &c.result,
                                stdout,
                                OUTPUT_MODE_IS_JSON(arg_output) ?
                                output_mode_to_json_format_flags(arg_output) | SD_JSON_FORMAT_COLOR_AUTO :
                                SD_JSON_FORMAT_OFF);

        /* Some unit types (e.g. targets or slices) do not have a Result property. For those, go by the unit
         * state instead. */
        if (isempty(c.result.result))
                return streq_ptr(c.result.active_state, "inactive") ? EXIT_SUCCESS : EXIT_FAILURE;

        return unit_result_to_exit_status(&c.result);
}
