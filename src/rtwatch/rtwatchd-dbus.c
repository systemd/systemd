/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>

#include "sd-bus.h"
#include "sd-event.h"

#include "bus-error.h"
#include "bus-get-properties.h"
#include "bus-locator.h"
#include "bus-log-control-api.h"
#include "bus-object.h"
#include "bus-polkit.h"
#include "bus-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "log.h"
#include "pidref.h"
#include "rtwatchd-dbus.h"
#include "rtwatchd-manager.h"
#include "threadref.h"

/* We implement the classic RealtimeKit D-Bus API, for compatibility with existing clients */
#define RTKIT_SERVICE_NAME "org.freedesktop.RealtimeKit1"
#define RTKIT_OBJECT_PATH  "/org/freedesktop/RealtimeKit1"
#define RTKIT_INTERFACE    "org.freedesktop.RealtimeKit1"

static int reply_errno(sd_bus_error *error, int r) {
        assert(r < 0);

        /* Existing clients of the RealtimeKit API look for these specific error names, hence map our
         * errors the same way RealtimeKit did. */

        if (ERRNO_IS_NEG_PRIVILEGE(r) || IN_SET(r, -ERANGE, -EUSERS, -EBUSY, -EAGAIN, -EOWNERDEAD))
                return sd_bus_error_set(error, SD_BUS_ERROR_ACCESS_DENIED, STRERROR(r));
        if (r == -ENOMEM)
                return sd_bus_error_set(error, SD_BUS_ERROR_NO_MEMORY, STRERROR(r));

        return sd_bus_error_set(error, SD_BUS_ERROR_FAILED, STRERROR(r));
}

static int property_get_rttime_usec_max(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *reterr_error) {

        Manager *m = ASSERT_PTR(userdata);

        assert(reply);

        return sd_bus_message_append(reply, "x", (int64_t) MIN(m->settings.rttime_max, (usec_t) INT64_MAX));
}

static int bus_get_client(
                sd_bus_message *message,
                uint64_t process,
                uint64_t thread,
                uid_t *ret_uid,
                ThreadRef *ret_thread,
                sd_bus_error *reterr_error) {

        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;
        _cleanup_(pidref_done) PidRef pid = PIDREF_NULL;
        uid_t uid;
        int r;

        assert(message);
        assert(ret_uid);
        assert(ret_thread);

        if (process != UINT64_MAX && (process == 0 || process > INT32_MAX))
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid process ID.");
        if (thread > INT32_MAX)
                return sd_bus_error_set(reterr_error, SD_BUS_ERROR_INVALID_ARGS, "Invalid thread ID.");

        /* Determine caller credentials */
        r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_PIDFD|SD_BUS_CREDS_AUGMENT, &creds);
        if (r < 0)
                return log_error_errno(r, "Failed to query caller credentials: %m");

        r = sd_bus_creds_get_euid(creds, &uid);
        if (r < 0)
                return log_error_errno(r, "Failed to get caller UID: %m");

        /* Pin the process and thread as early as possible, to make sure we operate on the right ones */
        if (process == UINT64_MAX) {
                r = bus_creds_get_pidref(creds, &pid);
                if (r < 0)
                        return log_error_errno(r, "Failed to get caller PID: %m");
        } else {
                r = pidref_set_pid(&pid, (pid_t) process);
                if (r < 0) {
                        log_debug_errno(r, "Failed to pin process " PID_FMT ": %m", (pid_t) process);
                        return reply_errno(reterr_error, r);
                }
        }

        r = threadref_set(&t, &pid, (pid_t) thread);
        if (r < 0) {
                log_debug_errno(r, "Failed to pin thread " PID_FMT " of process " PID_FMT ": %m", (pid_t) thread, pid.pid);
                return reply_errno(reterr_error, r);
        }

        *ret_uid = uid;
        *ret_thread = TAKE_THREADREF(t);
        return 0;
}

static int bus_make_thread_realtime(sd_bus_message *message, Manager *m, bool with_pid, sd_bus_error *error) {
        uint64_t process = UINT64_MAX, thread;
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;
        uint32_t priority;
        uid_t uid;
        int r;

        assert(message);
        assert(m);

        if (with_pid)
                r = sd_bus_message_read(message, "ttu", &process, &thread, &priority);
        else
                r = sd_bus_message_read(message, "tu", &thread, &priority);
        if (r < 0)
                return r;

        r = bus_get_client(message, process, thread, &uid, &t, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.RealtimeKit1.acquire-real-time",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_make_thread_realtime(m, uid, &t, priority);
        manager_notify_status(m);
        if (r < 0)
                return reply_errno(error, r);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

static int method_make_thread_realtime(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_make_thread_realtime(message, ASSERT_PTR(userdata), /* with_pid= */ false, error);
}

static int method_make_thread_realtime_with_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_make_thread_realtime(message, ASSERT_PTR(userdata), /* with_pid= */ true, error);
}

static int bus_make_thread_high_priority(sd_bus_message *message, Manager *m, bool with_pid, sd_bus_error *error) {
        uint64_t process = UINT64_MAX, thread;
        _cleanup_(threadref_done) ThreadRef t = THREADREF_NULL;
        int32_t nice_level;
        uid_t uid;
        int r;

        assert(message);
        assert(m);

        if (with_pid)
                r = sd_bus_message_read(message, "tti", &process, &thread, &nice_level);
        else
                r = sd_bus_message_read(message, "ti", &thread, &nice_level);
        if (r < 0)
                return r;

        r = bus_get_client(message, process, thread, &uid, &t, error);
        if (r < 0)
                return r;

        r = bus_verify_polkit_async(
                        message,
                        "org.freedesktop.RealtimeKit1.acquire-high-priority",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_make_thread_high_priority(m, uid, &t, nice_level);
        manager_notify_status(m);
        if (r < 0)
                return reply_errno(error, r);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

static int method_make_thread_high_priority(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_make_thread_high_priority(message, ASSERT_PTR(userdata), /* with_pid= */ false, error);
}

static int method_make_thread_high_priority_with_pid(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        return bus_make_thread_high_priority(message, ASSERT_PTR(userdata), /* with_pid= */ true, error);
}

static int bus_verify_manage(sd_bus_message *message, Manager *m, sd_bus_error *error) {
        assert(message);
        assert(m);

        /* The management methods are authorized via the same polkit action as their Varlink counterparts.
         * Returns > 0 if authorized, 0 if the polkit query is still ongoing (in which case the method is
         * called again once it completes), < 0 on error. */

        return bus_verify_polkit_async(
                        message,
                        "io.systemd.rtwatch.manage",
                        /* details= */ NULL,
                        &m->polkit_registry,
                        error);
}

static int method_reset_known(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_manage(message, m, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_reset_known(m);
        manager_notify_status(m);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

static int method_reset_all(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_manage(message, m, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        r = manager_reset_all(m);
        manager_notify_status(m);
        if (r < 0)
                return reply_errno(error, r);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

static int method_suspend(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_manage(message, m, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_suspend(m);
        manager_notify_status(m);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

static int method_resume(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = bus_verify_manage(message, m, error);
        if (r < 0)
                return r;
        if (r == 0)
                return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

        manager_resume(m);
        manager_notify_status(m);

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

/* Note that Exit() is not marked SD_BUS_VTABLE_UNPRIVILEGED, hence sd-bus only lets privileged clients call
 * it. It has no Varlink counterpart. */
static int method_exit(sd_bus_message *message, void *userdata, sd_bus_error *error) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(message);

        r = sd_event_exit(m->event, /* code= */ 0);
        if (r < 0)
                return r;

        return sd_bus_reply_method_return(message, /* types= */ NULL);
}

static const sd_bus_vtable manager_vtable[] = {
        SD_BUS_VTABLE_START(0),

        SD_BUS_PROPERTY("RTTimeUSecMax", "x", property_get_rttime_usec_max, 0, SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MaxRealtimePriority", "i", bus_property_get_int, offsetof(Manager, settings.max_realtime_priority), SD_BUS_VTABLE_PROPERTY_CONST),
        SD_BUS_PROPERTY("MinNiceLevel", "i", bus_property_get_int, offsetof(Manager, settings.min_nice_level), SD_BUS_VTABLE_PROPERTY_CONST),

        SD_BUS_METHOD_WITH_ARGS("MakeThreadRealtime",
                                SD_BUS_ARGS("t", thread, "u", priority),
                                SD_BUS_NO_RESULT,
                                method_make_thread_realtime,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MakeThreadRealtimeWithPID",
                                SD_BUS_ARGS("t", process, "t", thread, "u", priority),
                                SD_BUS_NO_RESULT,
                                method_make_thread_realtime_with_pid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MakeThreadHighPriority",
                                SD_BUS_ARGS("t", thread, "i", nice_level),
                                SD_BUS_NO_RESULT,
                                method_make_thread_high_priority,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD_WITH_ARGS("MakeThreadHighPriorityWithPID",
                                SD_BUS_ARGS("t", process, "t", thread, "i", nice_level),
                                SD_BUS_NO_RESULT,
                                method_make_thread_high_priority_with_pid,
                                SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetKnown", NULL, NULL, method_reset_known, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("ResetAll", NULL, NULL, method_reset_all, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Suspend", NULL, NULL, method_suspend, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Resume", NULL, NULL, method_resume, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("Exit", NULL, NULL, method_exit, 0),

        SD_BUS_VTABLE_END,
};

const BusObjectImplementation manager_object = {
        RTKIT_OBJECT_PATH,
        RTKIT_INTERFACE,
        .vtables = BUS_VTABLES(manager_vtable),
};

static int manager_inhibit_sleep(Manager *m);

static int on_inhibit_reply(sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        const sd_bus_error *e;
        int fd, r;

        assert(reply);

        m->inhibit_slot = sd_bus_slot_unref(m->inhibit_slot);

        e = sd_bus_message_get_error(reply);
        if (e) {
                log_notice("Could not set up logind system suspend handling, ignoring: %s",
                           bus_error_message(e, sd_bus_message_get_errno(reply)));
                return 0;
        }

        r = sd_bus_message_read(reply, "h", &fd);
        if (r < 0) {
                bus_log_parse_error_debug(r);
                return 0;
        }

        fd = fcntl(fd, F_DUPFD_CLOEXEC, 3);
        if (fd < 0) {
                log_warning_errno(errno, "Failed to duplicate sleep inhibitor fd, ignoring: %m");
                return 0;
        }

        close_and_replace(m->inhibit_fd, fd);
        log_debug("Acquired sleep inhibitor lock.");
        return 0;
}

static int manager_inhibit_sleep(Manager *m) {
        int r;

        assert(m);

        if (m->inhibit_fd >= 0 || m->inhibit_slot)
                return 0;

        r = bus_call_method_async(
                        m->bus,
                        &m->inhibit_slot,
                        bus_login_mgr,
                        "Inhibit",
                        on_inhibit_reply,
                        m,
                        "ssss",
                        "sleep",
                        "Realtime Watchdog",
                        "Demote realtime scheduling and stop canary.",
                        "delay");
        if (r < 0)
                return log_warning_errno(r, "Failed to acquire sleep inhibitor lock, ignoring: %m");

        return 0;
}

static int on_prepare_for_sleep(sd_bus_message *message, void *userdata, sd_bus_error *reterr_error) {
        Manager *m = ASSERT_PTR(userdata);
        int b, r;

        assert(message);

        r = sd_bus_message_read(message, "b", &b);
        if (r < 0) {
                bus_log_parse_error(r);
                return 0;
        }

        if (b) {
                manager_suspend(m);

                /* Release the delay lock, so that the system can go to sleep now */
                m->inhibit_fd = safe_close(m->inhibit_fd);
        } else {
                (void) manager_inhibit_sleep(m);
                manager_resume(m);
        }

        manager_notify_status(m);
        return 0;
}

int manager_connect_bus(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->bus);

        r = bus_open_system_watch_bind_with_description(&m->bus, "bus-api-rtwatch");
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = bus_add_implementation(m->bus, &manager_object, m);
        if (r < 0)
                return r;

        r = bus_log_control_api_register(m->bus);
        if (r < 0)
                return r;

        r = bus_match_signal_async(
                        m->bus,
                        &m->prepare_for_sleep_slot,
                        bus_login_mgr,
                        "PrepareForSleep",
                        on_prepare_for_sleep,
                        /* install_callback= */ NULL,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to request match for PrepareForSleep(): %m");

        r = manager_inhibit_sleep(m);
        if (r < 0)
                return r;

        r = sd_bus_request_name_async(m->bus, /* ret_slot= */ NULL, RTKIT_SERVICE_NAME, /* flags= */ 0, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to request name: %m");

        r = sd_bus_attach_event(m->bus, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        return 0;
}
