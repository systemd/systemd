/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "list.h"
#include "log.h"
#include "pidref.h"
#include "process-util.h"
#include "set.h"
#include "string-table.h"
#include "strv.h"
#include "threadref.h"
#include "user-util.h"
#include "rtwatchd-manager.h"
#include "rtwatchd-varlink.h"
#include "varlink-io.systemd.RTWatch.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

assert_cc(sizeof(pid_t) == sizeof(int32_t));

static const char* const watch_event_table[_WATCH_EVENT_MAX] = {
        [WATCH_EVENT_READY]         = "ready",
        [WATCH_EVENT_REALTIME]      = "realtime",
        [WATCH_EVENT_HIGH_PRIORITY] = "high-priority",
        [WATCH_EVENT_RESET_KNOWN]   = "reset-known",
        [WATCH_EVENT_RESET_ALL]     = "reset-all",
        [WATCH_EVENT_SUSPENDED]     = "suspended",
        [WATCH_EVENT_RESUMED]       = "resumed",
        [WATCH_EVENT_STARVING]      = "starving",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(watch_event, WatchEvent);

typedef struct MakeThreadParameters {
        ThreadRef thread; /* Not pinned until vl_get_client() is called. Until then .thread_pidfd_id is the
                           * inode number the client specified, if any, which is validated when pinning. */
        int value;
} MakeThreadParameters;

static void make_thread_parameters_done(MakeThreadParameters *p) {
        assert(p);

        threadref_done(&p->thread);
}

static int json_dispatch_thread_id(const char *name, sd_json_variant *variant, sd_json_dispatch_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "process", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,    offsetof(ThreadRef, process),         SD_JSON_NULLABLE|SD_JSON_STRICT },
                { "tid",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int32,  offsetof(ThreadRef, thread_id),       SD_JSON_NULLABLE                },
                { "pidfdId", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(ThreadRef, thread_pidfd_id), SD_JSON_NULLABLE                },
                {}
        };

        ThreadRef *t = ASSERT_PTR(userdata);
        int r;

        /* Parses a ThreadId object into an unpinned ThreadRef, see vl_get_client(). The process is pinned
         * right away, as usual. */

        threadref_done(t);

        if (sd_json_variant_is_null(variant))
                return 0;

        r = sd_json_dispatch(variant, dispatch_table, flags, t);
        if (r < 0)
                return r;

        /* Zero (or unset) refers to the main thread of the process */
        if (t->thread_id != 0 && !pid_is_valid(t->thread_id))
                return json_log(variant, flags, SYNTHETIC_ERRNO(EINVAL), "JSON field '%s' does not contain a valid thread ID.", strna(name));

        return 0;
}

static int json_variant_new_thread_id(sd_json_variant **ret, ThreadRef *t) {
        int r;

        assert(ret);
        assert(threadref_is_set(t));

        /* Turns a ThreadRef into a ThreadId object, i.e. the process' ProcessId plus the TID and the inode
         * number of the thread pidfd, if available. The boot ID of the process applies to the latter too. */

        r = threadref_acquire_pidfd_id(t);
        if (r < 0 && r != -ENOMEDIUM && !ERRNO_IS_NEG_NOT_SUPPORTED(r))
                return r;

        return sd_json_buildo(
                        ret,
                        JSON_BUILD_PAIR_PIDREF("process", &t->process),
                        SD_JSON_BUILD_PAIR_INTEGER("tid", t->thread_id),
                        SD_JSON_BUILD_PAIR_CONDITION(t->thread_pidfd_id > 0, "pidfdId", SD_JSON_BUILD_UNSIGNED(t->thread_pidfd_id)));
}

static int thread_build_json(TrackedThread *t, WatchEvent event, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *thread = NULL;
        _cleanup_free_ char *unit = NULL, *user_unit = NULL, *thread_name = NULL;
        _cleanup_strv_free_ char **command_line = NULL;
        int r;

        assert(t);
        assert(ret);

        /* Builds the description of a thread, as returned by List() and by Watch() (in which case 'event'
         * is set). Note that the auxiliary information is best effort: the process or thread might have
         * just exited, or might not be part of any unit. */

        TrackedProcess *p = ASSERT_PTR(t->process);

        r = cg_pidref_get_unit(&p->pid, &unit);
        if (r < 0)
                log_debug_errno(r, "Failed to get unit of process " PID_FMT ", ignoring: %m", p->pid.pid);

        r = cg_pidref_get_user_unit(&p->pid, &user_unit);
        if (r < 0)
                log_debug_errno(r, "Failed to get user unit of process " PID_FMT ", ignoring: %m", p->pid.pid);

        r = pidref_get_cmdline_strv(&p->pid, /* flags= */ 0, &command_line);
        if (r < 0)
                log_debug_errno(r, "Failed to get command line of process " PID_FMT ", ignoring: %m", p->pid.pid);

        r = threadref_get_comm(&t->thread, &thread_name);
        if (r < 0)
                log_debug_errno(r, "Failed to get name of thread " PID_FMT ", ignoring: %m", t->thread.thread_id);

        r = json_variant_new_thread_id(&thread, &t->thread);
        if (r < 0)
                return r;

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_CONDITION(event >= 0, "event", JSON_BUILD_STRING_UNDERSCORIFY(watch_event_to_string(event))),
                        SD_JSON_BUILD_PAIR_UNSIGNED("userId", ASSERT_PTR(p->user)->uid),
                        SD_JSON_BUILD_PAIR_VARIANT("thread", thread),
                        SD_JSON_BUILD_PAIR_CONDITION(t->realtime_priority >= 0, "priority", SD_JSON_BUILD_INTEGER(t->realtime_priority)),
                        SD_JSON_BUILD_PAIR_CONDITION(t->realtime_priority < 0, "niceLevel", SD_JSON_BUILD_INTEGER(t->nice_level)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("unit", unit),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("userUnit", user_unit),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("commandLine", command_line),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("threadName", thread_name));
}

static int reply_errno(sd_varlink *link, int r) {
        assert(link);
        assert(r < 0);

        switch (r) {

        case -ESRCH:
                return sd_varlink_error(link, "io.systemd.RTWatch.NoSuchProcess", /* parameters= */ NULL);

        case -ENXIO:
                return sd_varlink_error(link, "io.systemd.RTWatch.NoSuchThread", /* parameters= */ NULL);

        case -EPERM:
        case -EACCES:
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        case -ERANGE:
                return sd_varlink_error(link, "io.systemd.RTWatch.RealtimeTimeLimitNotSet", /* parameters= */ NULL);

        case -EUSERS:
                return sd_varlink_error(link, "io.systemd.RTWatch.LimitReached", /* parameters= */ NULL);

        case -EBUSY:
                return sd_varlink_error(link, "io.systemd.RTWatch.TooManyRequests", /* parameters= */ NULL);

        case -EAGAIN:
                return sd_varlink_error(link, "io.systemd.RTWatch.Suspended", /* parameters= */ NULL);

        case -EOWNERDEAD:
                return sd_varlink_error(link, "io.systemd.RTWatch.RecoveringFromLockup", /* parameters= */ NULL);

        default:
                return r;
        }
}

static int vl_get_client(sd_varlink *link, MakeThreadParameters *p, uid_t *ret_uid) {
        uid_t uid;
        int r;

        assert(link);
        assert(p);
        assert(ret_uid);

        /* Determines the caller's UID, and pins the thread to operate on. The process has already been
         * pinned when dispatching, if it was specified explicitly. If not, the peer process is used. */

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer UID: %m");

        if (!pidref_is_set(&p->thread.process)) {
                r = varlink_get_peer_pidref(link, &p->thread.process);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get peer PID: %m");
        }

        _cleanup_(threadref_done) ThreadRef pinned = THREADREF_NULL;
        r = threadref_set_full(&pinned, &p->thread.process, p->thread.thread_id, p->thread.thread_pidfd_id);
        if (r < 0) {
                log_debug_errno(r, "Failed to pin thread " PID_FMT " of process " PID_FMT ": %m",
                                p->thread.thread_id, p->thread.process.pid);
                return reply_errno(link, r);
        }

        threadref_done(&p->thread);
        p->thread = TAKE_THREADREF(pinned);

        *ret_uid = uid;
        return 1;
}

static int vl_method_make_thread_realtime(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "thread",   SD_JSON_VARIANT_OBJECT,        json_dispatch_thread_id, offsetof(MakeThreadParameters, thread), SD_JSON_NULLABLE  },
                { "priority", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(MakeThreadParameters, value),  SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        _cleanup_(make_thread_parameters_done) MakeThreadParameters p = {
                .thread = THREADREF_NULL,
        };
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!sched_priority_is_valid(m->settings.sched_policy, p.value) || p.value > m->settings.max_realtime_priority)
                return sd_varlink_error_invalid_parameter_name(link, "priority");

        r = vl_get_client(link, &p, &uid);
        if (r <= 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.RealtimeKit1.acquire-real-time",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = manager_make_thread_realtime(m, uid, &p.thread, (uint32_t) p.value);
        manager_notify_status(m);
        if (r < 0)
                return reply_errno(link, r);

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int vl_method_make_thread_high_priority(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        static const sd_json_dispatch_field dispatch_table[] = {
                { "thread",    SD_JSON_VARIANT_OBJECT,        json_dispatch_thread_id, offsetof(MakeThreadParameters, thread), SD_JSON_NULLABLE  },
                { "niceLevel", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,    offsetof(MakeThreadParameters, value),  SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        _cleanup_(make_thread_parameters_done) MakeThreadParameters p = {
                .thread = THREADREF_NULL,
        };
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid;
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!nice_is_valid(p.value) || p.value < m->settings.min_nice_level)
                return sd_varlink_error_invalid_parameter_name(link, "niceLevel");

        r = vl_get_client(link, &p, &uid);
        if (r <= 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.RealtimeKit1.acquire-high-priority",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = manager_make_thread_high_priority(m, uid, &p.thread, p.value);
        manager_notify_status(m);
        if (r < 0)
                return reply_errno(link, r);

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int vl_verify_polkit(sd_varlink *link, sd_json_variant *parameters, Manager *m, const char *action) {
        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        int r;

        assert(link);
        assert(m);
        assert(action);

        /* For methods that take no parameters but the polkit one: validates the parameters and checks
         * authorization. Returns > 0 if authorized, 0 if a reply was already sent or the polkit query is
         * still ongoing (in which case the method is called again once it completes), < 0 on error. */

        r = sd_varlink_dispatch(link, parameters, dispatch_table, /* userdata= */ NULL);
        if (r != 0)
                return r;

        return varlink_verify_polkit_async(
                        link,
                        m->bus,
                        action,
                        /* details= */ NULL,
                        &m->polkit_registry);
}

static int vl_method_reset_known(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = vl_verify_polkit(link, parameters, m, "io.systemd.rtwatch.manage");
        if (r <= 0)
                return r;

        manager_reset_known(m);
        manager_notify_status(m);

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int vl_method_reset_all(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = vl_verify_polkit(link, parameters, m, "io.systemd.rtwatch.manage");
        if (r <= 0)
                return r;

        r = manager_reset_all(m);
        manager_notify_status(m);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int vl_method_suspend(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = vl_verify_polkit(link, parameters, m, "io.systemd.rtwatch.manage");
        if (r <= 0)
                return r;

        manager_suspend(m);
        manager_notify_status(m);

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int vl_method_resume(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = vl_verify_polkit(link, parameters, m, "io.systemd.rtwatch.manage");
        if (r <= 0)
                return r;

        manager_resume(m);
        manager_notify_status(m);

        return sd_varlink_reply(link, /* parameters= */ NULL);
}

static int vl_method_describe(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        /* Note that these fields are only ever modified from the main thread, hence no need to take the
         * lock here */

        usec_t n;
        assert_se(sd_event_now(m->event, CLOCK_MONOTONIC, &n) >= 0);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("schedulingPolicy", sched_policy_to_string(m->settings.sched_policy)),
                        SD_JSON_BUILD_PAIR_INTEGER("maxRealtimePriority", m->settings.max_realtime_priority),
                        SD_JSON_BUILD_PAIR_INTEGER("minNiceLevel", m->settings.min_nice_level),
                        SD_JSON_BUILD_PAIR_UNSIGNED("maxRealtimeTimeUSec", m->settings.rttime_max),
                        SD_JSON_BUILD_PAIR_BOOLEAN("suspended", m->suspended),
                        SD_JSON_BUILD_PAIR_CONDITION(m->refuse_until > n, "refuseUntilUSec", SD_JSON_BUILD_UNSIGNED(m->refuse_until)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("users", hashmap_size(m->users)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("processes", m->n_processes),
                        SD_JSON_BUILD_PAIR_UNSIGNED("threads", m->n_threads));
}

static int vl_method_list(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        uid_t uid = UID_INVALID;
        TrackedUser *u;
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE)); /* Enforced by the IDL */

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        /* Privileged clients see all threads, unprivileged ones only those of their own processes */
        r = varlink_check_peer_privilege(link);
        if (r < 0)
                return r;
        if (r == 0) {
                r = sd_varlink_get_peer_uid(link, &uid);
                if (r < 0)
                        return r;
        }

        /* An empty list is not an error, hence send an empty reply in that case */
        r = sd_varlink_set_sentinel(link, /* error_id= */ NULL);
        if (r < 0)
                return r;

        _unused_ _cleanup_(manager_unlockp) Manager *locked = manager_lock(m);

        /* Don't report threads that are gone or have been demoted by others in the meantime */
        manager_gc(m, /* reset= */ false);

        HASHMAP_FOREACH(u, m->users) {
                if (uid_is_valid(uid) && u->uid != uid)
                        continue;

                LIST_FOREACH(processes, p, u->processes)
                        LIST_FOREACH(threads, t, p->threads) {
                                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                                /* Skip threads we never successfully promoted */
                                if (t->realtime_priority < 0 && t->nice_level >= 0)
                                        continue;

                                r = thread_build_json(t, _WATCH_EVENT_INVALID, &v);
                                if (r < 0)
                                        return r;

                                r = sd_varlink_reply(link, v);
                                if (r < 0)
                                        return r;
                        }
        }

        manager_notify_status(m);
        return 0;
}

static int vl_method_watch(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE)); /* Enforced by the IDL */

        /* Events include the PIDs and UIDs of other users' processes, hence this is privileged */
        r = vl_verify_polkit(link, parameters, m, "io.systemd.rtwatch.watch");
        if (r <= 0)
                return r;

        /* Let the client know that the subscription is established: everything that happens after it
         * received this message will be reported. */
        r = sd_varlink_notifybo(
                        link,
                        JSON_BUILD_PAIR_ENUM("event", watch_event_to_string(WATCH_EVENT_READY)));
        if (r < 0)
                return r;

        r = set_ensure_put(&m->watch_links, &varlink_hash_ops, link);
        if (r < 0)
                return r;
        sd_varlink_ref(link);

        log_debug("%u clients now watching events.", set_size(m->watch_links));
        return 0;
}

static void vl_on_disconnect(sd_varlink_server *s, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(link);

        sd_varlink_unref(set_remove(m->watch_links, link));
}

static void manager_send_event_full(Manager *m, sd_json_variant *v) {
        int r;

        assert(m);
        assert(v);

        r = varlink_many_notify(m->watch_links, v);
        if (r < 0)
                log_warning_errno(r, "Failed to notify watchers, ignoring: %m");
}

void manager_send_thread_event(Manager *m, WatchEvent event, TrackedThread *t) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(m);
        assert(IN_SET(event, WATCH_EVENT_REALTIME, WATCH_EVENT_HIGH_PRIORITY));
        assert(t);

        if (set_isempty(m->watch_links))
                return;

        r = thread_build_json(t, event, &v);
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to build event, ignoring: %m");

        manager_send_event_full(m, v);
}

void manager_send_event(Manager *m, WatchEvent event, unsigned n_threads) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r;

        assert(m);
        assert(IN_SET(event, WATCH_EVENT_RESET_KNOWN, WATCH_EVENT_RESET_ALL, WATCH_EVENT_SUSPENDED, WATCH_EVENT_RESUMED, WATCH_EVENT_STARVING));

        if (set_isempty(m->watch_links))
                return;

        r = sd_json_buildo(
                        &v,
                        JSON_BUILD_PAIR_ENUM("event", watch_event_to_string(event)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("affectedThreads", n_threads),
                        SD_JSON_BUILD_PAIR_CONDITION(event == WATCH_EVENT_STARVING, "refuseUntilUSec", SD_JSON_BUILD_UNSIGNED(m->refuse_until)));
        if (r < 0)
                return (void) log_warning_errno(r, "Failed to build event, ignoring: %m");

        manager_send_event_full(m, v);
}

int manager_connect_varlink(Manager *m) {
        int r;

        assert(m);
        assert(m->event);
        assert(!m->varlink_server);

        r = varlink_server_new(
                        &m->varlink_server,
                        SD_VARLINK_SERVER_ACCOUNT_UID|SD_VARLINK_SERVER_INHERIT_USERDATA,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_RTWatch,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.RTWatch.MakeThreadRealtime",     vl_method_make_thread_realtime,
                        "io.systemd.RTWatch.MakeThreadHighPriority", vl_method_make_thread_high_priority,
                        "io.systemd.RTWatch.ResetKnown",             vl_method_reset_known,
                        "io.systemd.RTWatch.ResetAll",               vl_method_reset_all,
                        "io.systemd.RTWatch.Suspend",                vl_method_suspend,
                        "io.systemd.RTWatch.Resume",                 vl_method_resume,
                        "io.systemd.RTWatch.Describe",               vl_method_describe,
                        "io.systemd.RTWatch.List",                   vl_method_list,
                        "io.systemd.RTWatch.Watch",                  vl_method_watch,
                        "io.systemd.service.Ping",                   varlink_method_ping,
                        "io.systemd.service.SetLogLevel",            varlink_method_set_log_level,
                        "io.systemd.service.GetLogLevel",            varlink_method_get_log_level,
                        "io.systemd.service.GetEnvironment",         varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink method calls: %m");

        r = sd_varlink_server_bind_disconnect(m->varlink_server, vl_on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink disconnect handler: %m");

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        /* We run unprivileged, hence cannot bind the socket ourselves, and rely on socket activation
         * instead. If we are activated via D-Bus only, the socket unit passes the socket to us
         * nonetheless. */
        r = sd_varlink_server_listen_auto(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0)
                log_debug("No Varlink socket passed, not providing a Varlink interface.");

        return 0;
}
