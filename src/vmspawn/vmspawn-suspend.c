/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-future.h"

#include "alloc-util.h"
#include "bus-locator.h"
#include "fd-util.h"
#include "log.h"
#include "qmp-client.h"
#include "vmspawn-qmp.h"
#include "vmspawn-suspend.h"

typedef struct VmspawnSuspendFiberData {
        sd_bus *bus;
        VmspawnQmpBridge *bridge;
} VmspawnSuspendFiberData;

static int acquire_sleep_inhibitor(sd_bus *bus, int *ret_fd) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        int fd, r;

        assert(bus);
        assert(ret_fd);

        r = bus_call_method(bus, bus_login_mgr, "Inhibit", /* reterr_error= */ NULL, &reply,
                            "ssss",
                            "sleep",
                            "systemd-vmspawn",
                            "Pause VM before host suspend so guest monotonic clock stays consistent",
                            "delay");
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(reply, SD_BUS_TYPE_UNIX_FD, &fd);
        if (r < 0)
                return r;

        /* Dup so the lifetime is detached from the sd_bus_message we're about to drop. */
        int dup = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (dup < 0)
                return -errno;

        *ret_fd = dup;
        return 0;
}

static int suspend_handler_fiber(void *userdata) {
        VmspawnSuspendFiberData *d = ASSERT_PTR(userdata);
        int r;

        /* Buffer up to a handful of in-flight signals so the bus callback can deposit them
         * without blocking even if we're mid-QMP-call. PrepareForSleep fires twice per
         * suspend cycle, so 8 covers several queued cycles. */
        _cleanup_(sd_channel_unrefp) sd_channel *signals = NULL;
        r = bus_match_signal_channel(d->bus, bus_login_mgr, "PrepareForSleep",
                                     /* capacity= */ 8, &signals);
        if (r < 0)
                return log_debug_errno(r, "Failed to subscribe to PrepareForSleep, suspend handling disabled: %m");

        _cleanup_close_ int inhibit_fd = -EBADF;
        r = acquire_sleep_inhibitor(d->bus, &inhibit_fd);
        if (r < 0)
                log_debug_errno(r, "Failed to acquire sleep delay inhibitor, VM will not block host suspend: %m");

        for (;;) {
                /* pop_latest collapses any backlog into the freshest PrepareForSleep payload:
                 * if the host went through multiple suspend/resume cycles while we were stuck in
                 * a QMP call, only the current state matters — acting on a stale `true` would
                 * pause a host-awake VM, and vice versa. */
                void *item;
                r = sd_channel_pop_latest(signals, &item);
                if (r == -ECANCELED || r == -EPIPE)
                        return 0;
                if (r < 0)
                        return log_warning_errno(r, "Failed to pop from PrepareForSleep queue, suspend handling stopped: %m");

                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = item;
                int going_to_sleep;

                r = sd_bus_message_read(m, "b", &going_to_sleep);
                if (r < 0)
                        return log_warning_errno(r, "Failed to parse PrepareForSleep payload, suspend handling stopped: %m");

                QmpClient *qmp = ASSERT_PTR(vmspawn_qmp_bridge_get_qmp(d->bridge));

                if (going_to_sleep) {
                        log_debug("Host preparing to sleep — pausing VM.");

                        r = qmp_client_call_and_log(qmp, "stop", QMP_CLIENT_ARGS(NULL), /* ret_result= */ NULL);
                        if (r >= 0)
                                log_debug("QMP stop acknowledged, releasing sleep inhibitor.");

                        inhibit_fd = safe_close(inhibit_fd);
                } else {
                        log_debug("Host resumed — resuming VM and re-arming sleep inhibitor.");

                        r = qmp_client_call_and_log(qmp, "cont", QMP_CLIENT_ARGS(NULL), /* ret_result= */ NULL);
                        if (r >= 0)
                                log_debug("QMP cont acknowledged.");

                        r = acquire_sleep_inhibitor(d->bus, &inhibit_fd);
                        if (r < 0)
                                log_warning_errno(r, "Failed to re-acquire sleep inhibitor, next suspend won't pause the VM: %m");
                }
        }
}

int vmspawn_suspend_handler_new(sd_bus *system_bus, VmspawnQmpBridge *bridge) {
        int r;

        assert(system_bus);
        assert(bridge);

        sd_event *event = ASSERT_PTR(sd_bus_get_event(system_bus));

        _cleanup_free_ VmspawnSuspendFiberData *d = new(VmspawnSuspendFiberData, 1);
        if (!d)
                return log_oom();

        *d = (VmspawnSuspendFiberData) {
                .bus = system_bus,
                .bridge = bridge,
        };

        _cleanup_(sd_future_cancel_unrefp) sd_future *fiber = NULL;
        r = sd_fiber_new(event, "vmspawn-suspend", suspend_handler_fiber, d, free, &fiber);
        if (r < 0)
                return log_debug_errno(r, "Failed to start suspend handler fiber: %m");

        TAKE_PTR(d);  /* now owned by the fiber via destroy=free */

        /* Make the fiber floating: the event loop owns the only ref, and the exit-source cascade
         * drives it to RESOLVED when the loop shuts down. Caller doesn't need a handle. */
        r = sd_fiber_set_floating(fiber, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to set suspend handler fiber floating: %m");

        fiber = sd_future_unref(fiber);
        return 0;
}
