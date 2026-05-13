/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "sd-bus.h"
#include "sd-event.h"
#include "sd-varlink.h"

#include "bus-common-errors.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "format-util.h"
#include "fs-util.h"
#include "hashmap.h"
#include "log.h"
#include "login-util.h"
#include "logind.h"
#include "logind-dbus.h"
#include "logind-inhibit.h"
#include "logind-session.h"
#include "logind-shutdown.h"
#include "logind-user.h"
#include "pidref.h"
#include "process-util.h"
#include "user-record.h"

int manager_have_multiple_sessions(
                Manager *m,
                uid_t uid) {

        Session *session;

        assert(m);

        /* Check for other users' sessions. Greeter sessions do not
         * count, and non-login sessions do not count either. */
        HASHMAP_FOREACH(session, m->sessions)
                if (SESSION_CLASS_IS_INHIBITOR_LIKE(session->class) &&
                    session->user->user_record->uid != uid)
                        return true;

        return false;
}

void log_shutdown_caller(const PidRef *caller, const char *method) {
        _cleanup_free_ char *comm = NULL, *unit = NULL;

        assert(method);

        if (!pidref_is_set(caller)) {
                return log_notice("%s requested from unknown client PID...", method);
        }

        (void) pidref_get_comm(caller, &comm);
        (void) cg_pidref_get_unit(caller, &unit);

        log_notice("%s requested from client PID " PID_FMT "%s%s%s%s%s%s...",
                   method, caller->pid,
                   comm ? " ('" : "", strempty(comm), comm ? "')" : "",
                   unit ? " (unit " : "", strempty(unit), unit ? ")" : "");
}

int manager_verify_shutdown_creds(
                Manager *m,
                sd_bus_message *message,
                sd_varlink *link,
                const HandleActionData *a,
                uint64_t flags,
                sd_bus_error *error) {

        bool multiple_sessions, blocked, interactive;
        _unused_ bool error_or_denial = false;
        Inhibitor *offending = NULL;
        uid_t uid;
        int r;

        assert(m);
        assert(a);
        assert(!!message != !!link); /* exactly one transport */
        assert(!link || !error); /* varlink doesn't use sd_bus_error */

        if (message) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                r = sd_bus_query_sender_creds(message, SD_BUS_CREDS_EUID, &creds);
                if (r < 0)
                        return r;

                r = sd_bus_creds_get_euid(creds, &uid);
                if (r < 0)
                        return r;
        } else {
                r = sd_varlink_get_peer_uid(link, &uid);
                if (r < 0)
                        return r;
        }

        r = manager_have_multiple_sessions(m, uid);
        if (r < 0)
                return r;

        multiple_sessions = r > 0;
        blocked = manager_is_inhibited(m, a->inhibit_what, NULL, /* flags= */ 0, uid, &offending);
        interactive = flags & SD_LOGIND_INTERACTIVE;

        if (multiple_sessions) {
                if (message)
                        r = bus_verify_polkit_async_full(
                                        message,
                                        a->polkit_action_multiple_sessions,
                                        /* details= */ NULL,
                                        /* good_user= */ UID_INVALID,
                                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                                        &m->polkit_registry,
                                        error);
                else
                        r = varlink_verify_polkit_async_full(
                                        link,
                                        m->bus,
                                        a->polkit_action_multiple_sessions,
                                        /* details= */ NULL,
                                        /* good_user= */ UID_INVALID,
                                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                                        &m->polkit_registry);

                if (r < 0) {
                        /* If we get -EBUSY, it means a polkit decision was made, but not for
                         * this action in particular. Assuming we are blocked on inhibitors,
                         * ignore that error and allow the decision to be revealed below. */
                        if (blocked && r == -EBUSY)
                                error_or_denial = true;
                        else
                                return r;
                }
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (blocked) {
                PolkitFlags polkit_flags = 0;

                /* With a strong inhibitor, if the skip flag is not set, reject outright.
                 * With a weak inhibitor, if root is asking and the root flag is set, reject outright.
                 * All else, check polkit first. */
                if (!FLAGS_SET(flags, SD_LOGIND_SKIP_INHIBITORS) &&
                    (offending->mode != INHIBIT_BLOCK_WEAK ||
                     (uid == 0 && FLAGS_SET(flags, SD_LOGIND_ROOT_CHECK_INHIBITORS)))) {
                        if (link)
                                return sd_varlink_errorbo(
                                                link,
                                                "io.systemd.Shutdown.BlockedByInhibitor",
                                                SD_JSON_BUILD_PAIR_STRING("who", offending->who),
                                                SD_JSON_BUILD_PAIR_STRING("why", offending->why));
                        if (error)
                                return sd_bus_error_set(error, BUS_ERROR_BLOCKED_BY_INHIBITOR_LOCK,
                                                        "Operation denied due to active block inhibitor");
                        return -EACCES;
                }

                /* We want to always ask here, even for root, to only allow bypassing if explicitly allowed
                 * by polkit, unless a weak blocker is used, in which case it will be authorized. */
                if (offending->mode != INHIBIT_BLOCK_WEAK)
                        polkit_flags |= POLKIT_ALWAYS_QUERY;

                if (interactive)
                        polkit_flags |= POLKIT_ALLOW_INTERACTIVE;

                if (message)
                        r = bus_verify_polkit_async_full(
                                        message,
                                        a->polkit_action_ignore_inhibit,
                                        /* details= */ NULL,
                                        /* good_user= */ UID_INVALID,
                                        polkit_flags,
                                        &m->polkit_registry,
                                        error);
                else
                        r = varlink_verify_polkit_async_full(
                                        link,
                                        m->bus,
                                        a->polkit_action_ignore_inhibit,
                                        /* details= */ NULL,
                                        /* good_user= */ UID_INVALID,
                                        polkit_flags,
                                        &m->polkit_registry);

                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        if (!multiple_sessions && !blocked) {
                if (message)
                        r = bus_verify_polkit_async_full(
                                        message,
                                        a->polkit_action,
                                        /* details= */ NULL,
                                        /* good_user= */ UID_INVALID,
                                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                                        &m->polkit_registry,
                                        error);
                else
                        r = varlink_verify_polkit_async_full(
                                        link,
                                        m->bus,
                                        a->polkit_action,
                                        /* details= */ NULL,
                                        /* good_user= */ UID_INVALID,
                                        interactive ? POLKIT_ALLOW_INTERACTIVE : 0,
                                        &m->polkit_registry);

                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */
        }

        /* If error_or_denial was set above, it means that a polkit denial or
         * error was deferred for a future call to bus_verify_polkit_async_full()
         * to catch. In any case, it also means that the payload guarded by
         * these polkit calls should never be executed, and hence we should
         * never reach this point. */
        assert(!error_or_denial);

        return 0;
}

void manager_reset_scheduled_shutdown(Manager *m) {
        assert(m);

        m->scheduled_shutdown_timeout_source = sd_event_source_disable_unref(m->scheduled_shutdown_timeout_source);
        m->wall_message_timeout_source = sd_event_source_disable_unref(m->wall_message_timeout_source);
        m->nologin_timeout_source = sd_event_source_disable_unref(m->nologin_timeout_source);

        m->scheduled_shutdown_action = _HANDLE_ACTION_INVALID;
        m->scheduled_shutdown_timeout = USEC_INFINITY;
        m->scheduled_shutdown_uid = UID_INVALID;
        m->scheduled_shutdown_tty = mfree(m->scheduled_shutdown_tty);
        m->shutdown_dry_run = false;

        if (m->unlink_nologin) {
                (void) unlink_or_warn("/run/nologin");
                m->unlink_nologin = false;
        }

        (void) unlink(SHUTDOWN_SCHEDULE_FILE);

        manager_send_changed(m, "ScheduledShutdown");
}
