/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "fd-util.h"
#include "format-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "login-util.h"
#include "logind.h"
#include "logind-dbus.h"
#include "logind-inhibit.h"
#include "logind-seat.h"
#include "logind-session.h"
#include "logind-shutdown.h"
#include "logind-user.h"
#include "logind-varlink.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-record.h"
#include "user-util.h"
#include "varlink-io.systemd.Login.h"
#include "varlink-io.systemd.Shutdown.h"
#include "varlink-io.systemd.service.h"
#include "varlink-util.h"

static int manager_varlink_get_session_by_peer(
                Manager *m,
                sd_varlink *link,
                bool consult_display,
                Session **ret) {

        int r;

        assert(m);
        assert(link);
        assert(ret);

        /* Determines the session of the peer. If the peer is not part of a session, but consult_display is
         * true, then will return the display session of the peer's owning user. Returns 0 with *ret set to
         * NULL if no session could be determined; the caller decides which error to report to the client. */

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire peer PID: %m");

        Session *session = NULL;
        _cleanup_free_ char *name = NULL;
        r = cg_pidref_get_session(&pidref, &name);
        if (r < 0) {
                if (!consult_display)
                        log_debug_errno(r, "Failed to acquire session of peer, giving up: %m");
                else {
                        log_debug_errno(r, "Failed to acquire session of peer, trying to find owner UID: %m");

                        uid_t uid;
                        r = cg_pidref_get_owner_uid(&pidref, &uid);
                        if (r < 0)
                                log_debug_errno(r, "Failed to acquire owning UID of peer, giving up: %m");
                        else {
                                User *user = hashmap_get(m->users, UID_TO_PTR(uid));
                                if (user)
                                        session = user->display;
                         }
                }
        } else
                session = hashmap_get(m->sessions, name);

        *ret = session;
        return 0;
}

static int manager_varlink_get_session_by_name_or_pidref(
                Manager *m,
                sd_varlink *link,
                const char *name,
                const PidRef *pidref,
                Session **ret) {

        int r;

        assert(m);
        assert(link);
        assert(ret);

        /* Resolves a session by name and/or PID. Supports the special names "self" and "auto" for the name
         * argument. If both name and pidref are unset, resolves to the caller's session. If both name and
         * pidref are set they must refer to the same session, otherwise -ESRCH is returned. Returns -ESRCH
         * on "not found". Caller is expected to turn that into a varlink error, typically via
         * sd_varlink_set_sentinel(). Returns negative errno on other failures. */

        Session *by_name = NULL;
        if (name) {
                if (session_is_self(name) || session_is_auto(name)) {
                        r = manager_varlink_get_session_by_peer(m, link, /* consult_display= */ session_is_auto(name), &by_name);
                        if (r < 0)
                                return r;
                        if (!by_name)
                                return -ESRCH;
                } else {
                        by_name = hashmap_get(m->sessions, name);
                        if (!by_name)
                                return -ESRCH;
                }
        }

        Session *by_pid = NULL;
        if (pidref && pidref_is_set(pidref)) {
                r = manager_get_session_by_pidref(m, pidref, &by_pid);
                if (r < 0)
                        return r;
                if (!by_pid)
                        return -ESRCH;
        }

        if (by_name && by_pid && by_name != by_pid)
                return -ESRCH;

        if (!by_name && !by_pid) {
                r = manager_varlink_get_session_by_peer(m, link, /* consult_display= */ true, &by_name);
                if (r < 0)
                        return r;
                if (!by_name)
                        return -ESRCH;
        }

        *ret = by_name ?: by_pid;
        return 0;
}

int session_send_create_reply_varlink(Session *s, const sd_bus_error *error) {
        assert(s);

        /* This is called after the session scope and the user service were successfully created, and
         * finishes where manager_create_session() left off. */

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = TAKE_PTR(s->create_link);
        if (!vl)
                return 0;

        if (sd_bus_error_is_set(error))
                return sd_varlink_error(vl, "io.systemd.Login.UnitAllocationFailed", /* parameters= */ NULL);

        log_debug("Sending Varlink reply about created session: "
                  "id=%s uid=" UID_FMT " runtime_path=%s seat=%s vtnr=%u",
                  s->id,
                  s->user->user_record->uid,
                  s->user->runtime_path,
                  s->seat ? s->seat->id : "",
                  s->vtnr);

        return sd_varlink_replybo(
                        vl,
                        SD_JSON_BUILD_PAIR_STRING("Id", s->id),
                        SD_JSON_BUILD_PAIR_STRING("RuntimePath", s->user->runtime_path),
                        SD_JSON_BUILD_PAIR_UNSIGNED("UID", s->user->user_record->uid),
                        SD_JSON_BUILD_PAIR_CONDITION(!!s->seat, "Seat", SD_JSON_BUILD_STRING(s->seat ? s->seat->id : NULL)),
                        SD_JSON_BUILD_PAIR_CONDITION(s->vtnr > 0, "VTNr", SD_JSON_BUILD_UNSIGNED(s->vtnr)),
                        JSON_BUILD_PAIR_ENUM("Class", session_class_to_string(s->class)),
                        JSON_BUILD_PAIR_ENUM("Type", session_type_to_string(s->type)));
}

static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_session_class, SessionClass, session_class_from_string);
static JSON_DISPATCH_ENUM_DEFINE(json_dispatch_session_type, SessionType, session_type_from_string);

typedef struct CreateSessionParameters {
        uid_t uid;
        PidRef pid;
        const char *service;
        SessionType type;
        SessionClass class;
        const char *desktop;
        const char *seat;
        unsigned vtnr;
        const char *tty;
        const char *display;
        int remote;
        const char *remote_user;
        const char *remote_host;
        char **extra_device_access;
} CreateSessionParameters;

static void create_session_parameters_done(CreateSessionParameters *p) {
        pidref_done(&p->pid);
        strv_free(p->extra_device_access);
}

static int vl_method_create_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID",               _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,      offsetof(CreateSessionParameters, uid),                 SD_JSON_MANDATORY },
                { "PID",               _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,          offsetof(CreateSessionParameters, pid),                 SD_JSON_STRICT    },
                { "Service",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, service),             0                 },
                { "Type",              SD_JSON_VARIANT_STRING,        json_dispatch_session_type,    offsetof(CreateSessionParameters, type),                SD_JSON_MANDATORY },
                { "Class",             SD_JSON_VARIANT_STRING,        json_dispatch_session_class,   offsetof(CreateSessionParameters, class),               SD_JSON_MANDATORY },
                { "Desktop",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, desktop),             SD_JSON_STRICT    },
                { "Seat",              SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, seat),                0                 },
                { "VTNr",              _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(CreateSessionParameters, vtnr),                0                 },
                { "TTY",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, tty),                 0                 },
                { "Display",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, display),             0                 },
                { "Remote",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(CreateSessionParameters, remote),              0                 },
                { "RemoteUser",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, remote_user),         0                 },
                { "RemoteHost",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, remote_host),         0                 },
                { "ExtraDeviceAccess", SD_JSON_VARIANT_ARRAY,         sd_json_dispatch_strv,         offsetof(CreateSessionParameters, extra_device_access), 0                 },
                {}
        };

        _cleanup_(create_session_parameters_done) CreateSessionParameters p = {
                .uid = UID_INVALID,
                .pid = PIDREF_NULL,
                .class = _SESSION_CLASS_INVALID,
                .type = _SESSION_TYPE_INVALID,
                .remote = -1,
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.class == SESSION_NONE)
                return sd_varlink_error_invalid_parameter_name(link, "Class");

        Seat *seat = NULL;
        if (p.seat) {
                seat = hashmap_get(m->seats, p.seat);
                if (!seat)
                        return sd_varlink_error(link, "io.systemd.Login.NoSuchSeat", /* parameters= */ NULL);
        }

        if (p.tty) {
                if (tty_is_vc(p.tty)) {
                        if (!seat)
                                seat = m->seat0;
                        else if (seat != m->seat0)
                                return sd_varlink_error_invalid_parameter_name(link, "Seat");

                        int v = vtnr_from_tty(p.tty);
                        if (v <= 0)
                                return sd_varlink_error_invalid_parameter_name(link, "TTY");

                        if (p.vtnr == 0)
                                p.vtnr = v;
                        else if (p.vtnr != (unsigned) v)
                                return sd_varlink_error_invalid_parameter_name(link, "VTNr");

                } else if (tty_is_console(p.tty)) {
                        if (!seat)
                                seat = m->seat0;
                        else if (seat != m->seat0)
                                return sd_varlink_error_invalid_parameter_name(link, "Seat");

                        if (p.vtnr != 0)
                                return sd_varlink_error_invalid_parameter_name(link, "VTNr");
                }
        }

        if (seat) {
                if (seat_has_vts(seat)) {
                        if (!vtnr_is_valid(p.vtnr))
                                return sd_varlink_error_invalid_parameter_name(link, "VTNr");
                } else {
                        if (p.vtnr != 0)
                                return sd_varlink_error_invalid_parameter_name(link, "VTNr");
                }
        }

        if (p.remote < 0)
                p.remote = p.remote_user || p.remote_host;

        /* Before we continue processing this, let's ensure the peer is privileged */
        r = varlink_check_privileged_peer(link);
        if (r < 0)
                return r;

        if (!pidref_is_set(&p.pid)) {
                r = varlink_get_peer_pidref(link, &p.pid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get peer pidref: %m");
        }

        if (p.pid.fd < 0)
                return sd_varlink_error(link, "io.systemd.Login.NoSessionPIDFD", /* parameters= */ NULL);

        Session *session;
        r = manager_create_session(
                        m,
                        p.uid,
                        &p.pid,
                        p.service,
                        p.type,
                        p.class,
                        p.desktop,
                        seat,
                        p.vtnr,
                        p.tty,
                        p.display,
                        p.remote,
                        p.remote_user,
                        p.remote_host,
                        p.extra_device_access,
                        &session);
        if (r == -EBUSY)
                return sd_varlink_error(link, "io.systemd.Login.AlreadySessionMember", /* parameters= */ NULL);
        if (r == -EADDRNOTAVAIL)
                return sd_varlink_error(link, "io.systemd.Login.VirtualTerminalAlreadyTaken", /* parameters= */ NULL);
        if (r == -EUSERS)
                return sd_varlink_error(link, "io.systemd.Login.TooManySessions", /* parameters= */ NULL);
        if (r < 0)
                return r;

        r = session_start(session, /* properties= */ NULL, /* error= */ NULL);
        if (r < 0)
                goto fail;

        session->create_link = sd_varlink_ref(link);

        /* Let's check if this is complete now */
        r = session_send_create_reply(session, /* error= */ NULL);
        if (r < 0)
                goto fail;

        return 1;

fail:
        if (session)
                session_add_to_gc_queue(session);

        return r;
}

static int emit_session_reply(sd_varlink *link, Session *session) {
        assert(link);
        assert(session);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r = session_build_json(session, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Session", v));
}

typedef struct ListSessionsParameters {
        const char *id;
        PidRef pidref;
} ListSessionsParameters;

static void list_sessions_parameters_done(ListSessionsParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
}

static int vl_method_list_sessions(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(ListSessionsParameters, id),     0 },
                { "PID", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,          offsetof(ListSessionsParameters, pidref), 0 },
                {}
        };

        _cleanup_(list_sessions_parameters_done) ListSessionsParameters p = {
                .pidref = PIDREF_NULL,
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchSession");
        if (r < 0)
                return r;

        /* Unique-key path: Id and/or PID provided. Single reply or NoSuchSession. */
        if (p.id || pidref_is_set(&p.pidref)) {
                Session *session;
                r = manager_varlink_get_session_by_name_or_pidref(m, link, p.id, &p.pidref, &session);
                if (r == -ESRCH)
                        return 0; /* triggers NoSuchSession sentinel */
                if (r != 0)
                        return r;

                return emit_session_reply(link, session);
        }

        /* Streaming path: no filter. Full list, requires 'more' flag. */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

        Session *session;
        HASHMAP_FOREACH(session, m->sessions) {
                r = emit_session_reply(link, session);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_varlink_resolve_peer_uid(sd_varlink *link, uid_t *ret) {
        assert(link);
        assert(ret);

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        int r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire peer PID: %m");

        uid_t uid;
        r = cg_pidref_get_owner_uid(&pidref, &uid);
        if (r == -ENOENT || r == -ENODATA || r == -ESRCH) {
                log_debug_errno(r, "Failed to acquire owning UID of peer: %m");
                return -ESRCH;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to acquire owning UID of peer: %m");

        *ret = uid;
        return 0;
}

static int manager_varlink_get_user_by_uid_or_pidref(
                Manager *m,
                sd_varlink *link,
                uid_t uid,
                const PidRef *pidref,
                User **ret) {

        int r;

        assert(m);
        assert(link);
        assert(ret);

        /* Resolves a user by UID and/or PID. If UID is UID_INVALID and pidref is unset, resolves to the
         * calling peer's UID. If both UID and pidref are set they must reference the same user, otherwise
         * -ESRCH is returned. Returns -ESRCH on "not found". Returns negative errno on other failures. */

        User *by_uid = NULL;
        if (uid_is_valid(uid)) {
                by_uid = hashmap_get(m->users, UID_TO_PTR(uid));
                if (!by_uid)
                        return -ESRCH;
        }

        User *by_pid = NULL;
        if (pidref && pidref_is_set(pidref)) {
                uid_t pid_uid;
                r = cg_pidref_get_owner_uid(pidref, &pid_uid);
                if (r == -ENOENT || r == -ENODATA || r == -ESRCH) {
                        log_debug_errno(r, "Failed to acquire owning UID of PID: %m");
                        return -ESRCH;
                }
                if (r < 0)
                        return log_debug_errno(r, "Failed to acquire owning UID of PID: %m");

                by_pid = hashmap_get(m->users, UID_TO_PTR(pid_uid));
                if (!by_pid)
                        return -ESRCH;
        }

        if (by_uid && by_pid && by_uid != by_pid)
                return -ESRCH;

        if (by_uid || by_pid) {
                *ret = by_uid ?: by_pid;
                return 0;
        }

        /* No filter set: resolve to caller's UID. */
        uid_t peer_uid;
        r = manager_varlink_resolve_peer_uid(link, &peer_uid);
        if (r < 0)
                return r; /* -ESRCH propagates as "not found" */

        User *peer_user = hashmap_get(m->users, UID_TO_PTR(peer_uid));
        if (!peer_user)
                return -ESRCH;

        *ret = peer_user;
        return 0;
}

static int emit_user_reply(sd_varlink *link, User *user) {
        assert(link);
        assert(user);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r = user_build_json(user, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("User", v));
}

typedef struct ListUsersParameters {
        uid_t uid;
        PidRef pidref;
} ListUsersParameters;

static void list_users_parameters_done(ListUsersParameters *p) {
        assert(p);
        pidref_done(&p->pidref);
}

static int vl_method_list_users(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, offsetof(ListUsersParameters, uid),    0 },
                { "PID", _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,     offsetof(ListUsersParameters, pidref), 0 },
                {}
        };

        _cleanup_(list_users_parameters_done) ListUsersParameters p = {
                .uid = UID_INVALID,
                .pidref = PIDREF_NULL,
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchUser");
        if (r < 0)
                return r;

        bool has_filter = uid_is_valid(p.uid) || pidref_is_set(&p.pidref);

        /* Single-reply path: either an explicit filter, or no filter + no 'more' flag (caller-UID
         * fallback preserves the DescribeUser ergonomic). */
        if (has_filter || !FLAGS_SET(flags, SD_VARLINK_METHOD_MORE)) {
                User *user;
                r = manager_varlink_get_user_by_uid_or_pidref(m, link, p.uid, &p.pidref, &user);
                if (r == -ESRCH)
                        return 0; /* triggers NoSuchUser sentinel */
                if (r != 0)
                        return r;

                return emit_user_reply(link, user);
        }

        /* Streaming path: no filter, 'more' flag set. Full list. */
        User *user;
        HASHMAP_FOREACH(user, m->users) {
                r = emit_user_reply(link, user);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_varlink_get_seat_by_name(
                Manager *m,
                sd_varlink *link,
                const char *name,
                Seat **ret) {

        int r;

        assert(m);
        assert(link);
        assert(ret);

        /* Resolves a seat name to a seat object. Supports the special names "self" and "auto" (and NULL,
         * which is treated like "auto" — i.e. the display session is consulted if the caller's own session
         * cannot be determined) — these resolve to the seat of the caller's session. Returns -ESRCH on "not
         * found". Caller is expected to turn that into a varlink error. */

        if (!name || seat_is_self(name) || seat_is_auto(name)) {
                Session *session;
                r = manager_varlink_get_session_by_peer(m, link, /* consult_display= */ !name || seat_is_auto(name), &session);
                if (r < 0)
                        return r;
                if (!session || !session->seat)
                        return -ESRCH;

                *ret = session->seat;
                return 0;
        }

        Seat *seat = hashmap_get(m->seats, name);
        if (!seat)
                return -ESRCH;

        *ret = seat;
        return 0;
}

static int emit_seat_reply(sd_varlink *link, Seat *seat) {
        assert(link);
        assert(seat);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        int r = seat_build_json(seat, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Seat", v));
}

static int vl_method_list_seats(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchSeat");
        if (r < 0)
                return r;

        /* Single-reply path: explicit Id, or no filter + no 'more' flag (caller-seat fallback preserves
         * the DescribeSeat ergonomic). */
        if (p.id || !FLAGS_SET(flags, SD_VARLINK_METHOD_MORE)) {
                Seat *seat;
                r = manager_varlink_get_seat_by_name(m, link, p.id, &seat);
                if (r == -ESRCH)
                        return 0; /* triggers NoSuchSeat sentinel */
                if (r != 0)
                        return r;

                return emit_seat_reply(link, seat);
        }

        /* Streaming path: no filter, 'more' flag set. Full list. */
        Seat *seat;
        HASHMAP_FOREACH(seat, m->seats) {
                r = emit_seat_reply(link, seat);
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_list_inhibitors(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        /* IDL uses SD_VARLINK_REQUIRES_MORE, so the framework rejects non-more calls before this handler. */

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        /* Required for multi-reply streaming: sd_varlink_reply() only stashes the previous reply (for
         * the 'continues' flag machinery) when v->sentinel is set. It also provides a clean terminator
         * when the inhibitor hashmap is empty. */
        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchInhibitor");
        if (r < 0)
                return r;

        Inhibitor *inhibitor;
        HASHMAP_FOREACH(inhibitor, m->inhibitors) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = inhibitor_build_json(inhibitor, &v);
                if (r < 0)
                        return r;

                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Inhibitor", v));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_release_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name_or_pidref(m, link, p.id, /* pidref= */ NULL, &session);
        if (r == -ESRCH)
                return sd_varlink_error(link, "io.systemd.Login.NoSuchSession", /* parameters= */ NULL);
        if (r != 0)
                return r;

        Session *peer_session;
        r = manager_varlink_get_session_by_peer(m, link, /* consult_display= */ false, &peer_session);
        if (r < 0)
                return r;
        if (!peer_session)
                return sd_varlink_error(link, "io.systemd.Login.NoSuchSession", /* parameters= */ NULL);

        if (session != peer_session)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        r = session_release(session);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int setup_wall_message_timer(Manager *m, sd_varlink *link) {
        uid_t uid = UID_INVALID;
        int r;

        (void) sd_varlink_get_peer_uid(link, &uid);
        m->scheduled_shutdown_uid = uid;

        _cleanup_free_ char *tty = NULL;
        pid_t pid = 0;
        r = sd_varlink_get_peer_pid(link, &pid);
        if (r >= 0)
                (void) get_ctty(pid, /* ret_devnr= */ NULL, &tty);

        r = free_and_strdup_warn(&m->scheduled_shutdown_tty, tty);
        if (r < 0)
                return log_oom();

        return manager_setup_wall_message_timer(m);
}

static int manager_do_shutdown_action(sd_varlink *link, sd_json_variant *parameters, HandleAction action) {
        Manager *m = ASSERT_PTR(sd_varlink_get_userdata(link));
        int skip_inhibitors = -1;
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "skipInhibitors", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate, 0, 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &skip_inhibitors);
        if (r != 0)
                return r;

        uint64_t flags = skip_inhibitors > 0 ? SD_LOGIND_SKIP_INHIBITORS : 0;

        const HandleActionData *a = handle_action_lookup(action);
        assert(a);

        r = manager_verify_shutdown_creds(m, /* message= */ NULL, link, a, flags, /* error= */ NULL);
        if (r != 0)
                return r;

        {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;

                (void) varlink_get_peer_pidref(link, &pidref);
                log_shutdown_caller(&pidref, handle_action_to_string(action));
        }

        if (m->delayed_action)
                return sd_varlink_error(link, "io.systemd.Shutdown.AlreadyInProgress", /* parameters= */ NULL);

        /* Reset in case we're short-circuiting a scheduled shutdown */
        m->unlink_nologin = false;
        manager_reset_scheduled_shutdown(m);

        m->scheduled_shutdown_timeout = 0;
        m->scheduled_shutdown_action = action;

        (void) setup_wall_message_timer(m, link);

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_manager_shutdown_or_sleep_now_or_later(m, a, &error);
        if (r < 0) {
                log_warning_errno(r, "Failed to execute %s: %s",
                                  handle_action_to_string(action),
                                  bus_error_message(&error, r));
                return sd_varlink_error_errno(link, r);
        }

        return sd_varlink_reply(link, NULL);
}

static int vl_method_power_off(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return manager_do_shutdown_action(link, parameters, HANDLE_POWEROFF);
}

static int vl_method_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return manager_do_shutdown_action(link, parameters, HANDLE_REBOOT);
}

static int vl_method_halt(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return manager_do_shutdown_action(link, parameters, HANDLE_HALT);
}

static int vl_method_kexec(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return manager_do_shutdown_action(link, parameters, HANDLE_KEXEC);
}

static int vl_method_soft_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return manager_do_shutdown_action(link, parameters, HANDLE_SOFT_REBOOT);
}

int manager_varlink_init(Manager *m, int fd) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        _unused_ _cleanup_close_ int fd_close = fd;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = varlink_server_new(
                        &s,
                        SD_VARLINK_SERVER_ACCOUNT_UID|
                        SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_Login,
                        &vl_interface_io_systemd_Shutdown,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add varlink interfaces: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Login.CreateSession",    vl_method_create_session,
                        "io.systemd.Login.ReleaseSession",   vl_method_release_session,
                        "io.systemd.Shutdown.PowerOff",      vl_method_power_off,
                        "io.systemd.Shutdown.Reboot",        vl_method_reboot,
                        "io.systemd.Shutdown.Halt",          vl_method_halt,
                        "io.systemd.Shutdown.KExec",         vl_method_kexec,
                        "io.systemd.Shutdown.SoftReboot",    vl_method_soft_reboot,
                        "io.systemd.Login.ListSessions",     vl_method_list_sessions,
                        "io.systemd.Login.ListUsers",        vl_method_list_users,
                        "io.systemd.Login.ListSeats",        vl_method_list_seats,
                        "io.systemd.Login.ListInhibitors",   vl_method_list_inhibitors,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        if (fd < 0)
                r = sd_varlink_server_listen_address(s, "/run/systemd/io.systemd.Login", /* mode= */ 0666);
        else
                r = sd_varlink_server_listen_fd(s, fd);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket '/run/systemd/io.systemd.Login': %m");

        TAKE_FD(fd_close);

        r = sd_varlink_server_attach_event(s, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach varlink connection to event loop: %m");

        m->varlink_server = TAKE_PTR(s);
        return 0;
}

void manager_varlink_done(Manager *m) {
        assert(m);

        m->varlink_server = sd_varlink_server_unref(m->varlink_server);
}
