/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "alloc-util.h"
#include "bus-locator.h"
#include "bus-util.h"
#include "fd-util.h"
#include "log.h"
#include "qmp-client.h"
#include "vmspawn-qmp.h"
#include "vmspawn-suspend.h"

struct VmspawnSuspendHandler {
        sd_bus *bus;                 /* non-owning */
        VmspawnQmpBridge *bridge;    /* non-owning */
        sd_bus_slot *prepare_slot;   /* PrepareForSleep match */
        int inhibit_fd;              /* logind delay inhibitor; -EBADF when not held */
};

/* QMP completion: log and move on. We never tear down the VM if pause/resume fails — losing
 * the watchdog-saving pause is better than losing the VM. */
static int on_qmp_log_only(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata) {

        const char *cmd = ASSERT_PTR(userdata);

        if (error < 0)
                log_warning_errno(error, "QMP %s failed: %s", cmd, strna(error_desc));
        else
                log_debug("QMP %s acknowledged.", cmd);
        return 0;
}

static int qmp_send_bare(VmspawnQmpBridge *bridge, const char *command) {
        QmpClient *qmp = vmspawn_qmp_bridge_get_qmp(bridge);
        if (!qmp)
                return -ENOTCONN;

        return qmp_client_invoke(qmp, /* ret_slot= */ NULL, command, QMP_CLIENT_ARGS(NULL),
                                 on_qmp_log_only, (void*) command);
}

static int acquire_sleep_inhibitor(sd_bus *bus, int *ret_fd) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int fd, r;

        assert(bus);
        assert(ret_fd);

        r = bus_call_method(bus, bus_login_mgr, "Inhibit", &error, &reply,
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
        *ret_fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (*ret_fd < 0)
                return -errno;

        return 0;
}

static int on_prepare_for_sleep(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        VmspawnSuspendHandler *h = ASSERT_PTR(userdata);
        int going_to_sleep, r;

        r = sd_bus_message_read(m, "b", &going_to_sleep);
        if (r < 0) {
                log_warning_errno(r, "Failed to parse PrepareForSleep payload, ignoring: %m");
                return 0;
        }

        if (going_to_sleep) {
                log_debug("Host preparing to sleep — pausing VM.");

                r = qmp_send_bare(h->bridge, "stop");
                if (r < 0)
                        log_warning_errno(r, "Failed to send QMP stop, host will suspend anyway: %m");

                /* Release the inhibitor so logind can proceed with the sleep. */
                h->inhibit_fd = safe_close(h->inhibit_fd);
        } else {
                log_debug("Host resumed — resuming VM and re-arming sleep inhibitor.");

                r = qmp_send_bare(h->bridge, "cont");
                if (r < 0)
                        log_warning_errno(r, "Failed to send QMP cont, VM is stuck paused: %m");

                /* Re-acquire the inhibitor for the next suspend cycle. */
                r = acquire_sleep_inhibitor(h->bus, &h->inhibit_fd);
                if (r < 0)
                        log_warning_errno(r, "Failed to re-acquire sleep inhibitor, next suspend won't pause the VM: %m");
        }

        return 0;
}

int vmspawn_suspend_handler_new(
                sd_bus *system_bus,
                VmspawnQmpBridge *bridge,
                VmspawnSuspendHandler **ret) {

        _cleanup_(vmspawn_suspend_handler_freep) VmspawnSuspendHandler *h = NULL;
        int r;

        assert(bridge);
        assert(ret);

        if (!system_bus) {
                log_debug("No system bus available, suspend handling disabled.");
                *ret = NULL;
                return 0;
        }

        h = new(VmspawnSuspendHandler, 1);
        if (!h)
                return -ENOMEM;

        *h = (VmspawnSuspendHandler) {
                .bus = system_bus,
                .bridge = bridge,
                .inhibit_fd = -EBADF,
        };

        r = acquire_sleep_inhibitor(system_bus, &h->inhibit_fd);
        if (r < 0)
                /* Logind may not be reachable (e.g. inside a container). Continue without
                 * suspend handling; we can still subscribe to the signal, but without the
                 * delay inhibitor the host may suspend before we get a chance to pause. */
                log_debug_errno(r, "Failed to acquire sleep delay inhibitor, VM will not be paused on host suspend: %m");

        r = bus_match_signal_async(
                        system_bus,
                        &h->prepare_slot,
                        bus_login_mgr,
                        "PrepareForSleep",
                        on_prepare_for_sleep, /* install_callback= */ NULL, h);
        if (r < 0) {
                log_debug_errno(r, "Failed to subscribe to PrepareForSleep, suspend handling disabled: %m");
                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(h);
        return 0;
}

VmspawnSuspendHandler* vmspawn_suspend_handler_free(VmspawnSuspendHandler *h) {
        if (!h)
                return NULL;

        h->prepare_slot = sd_bus_slot_unref(h->prepare_slot);
        h->inhibit_fd = safe_close(h->inhibit_fd);
        return mfree(h);
}
