/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"
#include "sd-event.h"

#include "alloc-util.h"
#include "bus-error.h"
#include "bus-polkit.h"
#include "cgroup-util.h"
#include "escape.h"
#include "devnum-util.h"
#include "efi-api.h"
#include "efi-loader.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "format-util.h"
#include "hashmap.h"
#include "json-util.h"
#include "login-util.h"
#include "virt.h"
#include "os-util.h"
#include "parse-util.h"
#include "logind.h"
#include "fs-util.h"
#include "logind-action.h"
#include "logind-dbus.h"
#include "logind-inhibit.h"
#include "logind-seat.h"
#include "logind-session.h"
#include "logind-session-dbus.h"
#include "logind-session-device.h"
#include "logind-shutdown.h"
#include "logind-user.h"
#include "logind-user-dbus.h"
#include "logind-varlink.h"
#include "mkdir-label.h"
#include "path-util.h"
#include "reboot-util.h"
#include "set.h"
#include "signal-util.h"
#include "sleep-config.h"
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

static int manager_varlink_get_session_by_name(
                Manager *m,
                sd_varlink *link,
                const char *name,
                Session **ret) {

        int r;

        assert(m);
        assert(link);
        assert(ret);

        /* Resolves a session name to a session object. Supports resolving the special names "self" and "auto". */

        if (session_is_self(name) || session_is_auto(name)) {
                Session *session;

                r = manager_varlink_get_session_by_peer(m, link, /* consult_display= */ session_is_auto(name), &session);
                if (r < 0)
                        return r;
                if (!session)
                        return sd_varlink_error(link, "io.systemd.Login.NoSuchSession", /* parameters= */ NULL);

                *ret = session;
                return 0;
        }

        Session *session = hashmap_get(m->sessions, name);
        if (!session)
                return sd_varlink_error(link, "io.systemd.Login.NoSuchSession", /* parameters= */ NULL);

        *ret = session;
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

static int vl_method_describe_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
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
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r != 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = session_build_json(session, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Session", v));
}

static int vl_method_list_sessions(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchSession");
        if (r < 0)
                return r;

        Session *session;
        HASHMAP_FOREACH(session, m->sessions) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = session_build_json(session, &v);
                if (r < 0)
                        return r;

                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Session", v));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int manager_varlink_get_user_by_uid(
                Manager *m,
                sd_varlink *link,
                uid_t uid,
                User **ret) {

        assert(m);
        assert(link);
        assert(ret);

        /* If UID is UID_INVALID, resolve to the calling peer's UID */
        if (!uid_is_valid(uid)) {
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                int r = varlink_get_peer_pidref(link, &pidref);
                if (r < 0)
                        return log_error_errno(r, "Failed to acquire peer PID: %m");

                r = cg_pidref_get_owner_uid(&pidref, &uid);
                if (r < 0) {
                        log_debug_errno(r, "Failed to acquire owning UID of peer: %m");
                        return sd_varlink_error(link, "io.systemd.Login.NoSuchUser", /* parameters= */ NULL);
                }
        }

        User *user = hashmap_get(m->users, UID_TO_PTR(uid));
        if (!user)
                return sd_varlink_error(link, "io.systemd.Login.NoSuchUser", /* parameters= */ NULL);

        *ret = user;
        return 0;
}

static int vl_method_describe_user(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                uid_t uid;
        } p = {
                .uid = UID_INVALID,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, voffsetof(p, uid), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        User *user;
        r = manager_varlink_get_user_by_uid(m, link, p.uid, &user);
        if (r != 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = user_build_json(user, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("User", v));
}

static int vl_method_list_users(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchUser");
        if (r < 0)
                return r;

        User *user;
        HASHMAP_FOREACH(user, m->users) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = user_build_json(user, &v);
                if (r < 0)
                        return r;

                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("User", v));
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

        assert(m);
        assert(link);
        assert(ret);

        /* Resolves a seat name to a seat object. Supports resolving the special names "self" and "auto",
         * which resolve to the seat of the caller's session. */

        if (seat_is_self(name) || seat_is_auto(name)) {
                Session *session;
                int r = manager_varlink_get_session_by_peer(m, link, /* consult_display= */ seat_is_auto(name), &session);
                if (r < 0)
                        return r;
                if (!session || !session->seat)
                        return sd_varlink_error(link, "io.systemd.Login.NoSuchSeat", /* parameters= */ NULL);

                *ret = session->seat;
                return 0;
        }

        Seat *seat = hashmap_get(m->seats, name);
        if (!seat)
                return sd_varlink_error(link, "io.systemd.Login.NoSuchSeat", /* parameters= */ NULL);

        *ret = seat;
        return 0;
}

static int vl_method_describe_seat(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
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

        Seat *seat;
        r = manager_varlink_get_seat_by_name(m, link, p.id, &seat);
        if (r != 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = seat_build_json(seat, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Seat", v));
}

static int vl_method_list_seats(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.Login.NoSuchSeat");
        if (r < 0)
                return r;

        Seat *seat;
        HASHMAP_FOREACH(seat, m->seats) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                r = seat_build_json(seat, &v);
                if (r < 0)
                        return r;

                r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Seat", v));
                if (r < 0)
                        return r;
        }

        return 0;
}

static int vl_method_activate_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

#if ENABLE_POLKIT
        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.chvt",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;
#endif

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_lock_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* If no session specified, lock all sessions */
        if (!p.id) {
                r = varlink_verify_polkit_async(
                                link,
                                m->bus,
                                "org.freedesktop.login1.lock-sessions",
                                /* details= */ NULL,
                                &m->polkit_registry);
                if (r <= 0)
                        return r;

                r = session_send_lock_all(m, /* lock= */ true);
                if (r < 0)
                        return r;

                return sd_varlink_reply(link, NULL);
        }

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        "org.freedesktop.login1.lock-sessions",
                        /* details= */ NULL,
                        session->user->user_record->uid,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = session_send_lock(session, /* lock= */ true);
        if (r == -ENOTTY)
                return sd_varlink_error(link, "io.systemd.Login.NotSupported", /* parameters= */ NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_unlock_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        /* If no session specified, unlock all sessions */
        if (!p.id) {
                r = varlink_verify_polkit_async(
                                link,
                                m->bus,
                                "org.freedesktop.login1.lock-sessions",
                                /* details= */ NULL,
                                &m->polkit_registry);
                if (r <= 0)
                        return r;

                r = session_send_lock_all(m, /* lock= */ false);
                if (r < 0)
                        return r;

                return sd_varlink_reply(link, NULL);
        }

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        "org.freedesktop.login1.lock-sessions",
                        /* details= */ NULL,
                        session->user->user_record->uid,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = session_send_lock(session, /* lock= */ false);
        if (r == -ENOTTY)
                return sd_varlink_error(link, "io.systemd.Login.NotSupported", /* parameters= */ NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_terminate_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        session->user->user_record->uid,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = session_stop(session, /* force= */ true);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_kill_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                const char *whom;
                int signo;
        } p = {
                .signo = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",     SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),    SD_JSON_MANDATORY },
                { "Whom",   SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, whom),  0                },
                { "Signal", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_signal, voffsetof(p, signo), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        KillWhom whom;
        if (isempty(p.whom))
                whom = KILL_ALL;
        else {
                whom = kill_whom_from_string(p.whom);
                if (whom < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "Whom");
        }

        if (!SIGNAL_VALID(p.signo))
                return sd_varlink_error_invalid_parameter_name(link, "Signal");

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        session->user->user_record->uid,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = session_kill(session, whom, p.signo, &error);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_idle_hint(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                bool idle_hint;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",       SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),        0                },
                { "IdleHint", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      voffsetof(p, idle_hint), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        /* Only the session owner or root may set idle hint */
        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != session->user->user_record->uid)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = session_set_idle_hint(session, p.idle_hint);
        if (r == -ENOTTY)
                return sd_varlink_error(link, "io.systemd.Login.NotSupported", /* parameters= */ NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_locked_hint(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                bool locked_hint;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",         SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),          0                },
                { "LockedHint", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_stdbool,      voffsetof(p, locked_hint), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        /* Only the session owner or root may set locked hint */
        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && uid != session->user->user_record->uid)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = session_set_locked_hint(session, p.locked_hint);
        if (r == -ENOTTY)
                return sd_varlink_error(link, "io.systemd.Login.NotSupported", /* parameters= */ NULL);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_take_control(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                int force;
        } p = {
                .force = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),    0 },
                { "Force", SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     voffsetof(p, force), 0 },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        bool force = p.force > 0;

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (uid != 0 && (force || uid != session->user->user_record->uid))
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        r = session_set_controller_varlink(session, link, force, /* prepare= */ true);
        if (r == -EBUSY)
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);
        if (r < 0)
                return r;

        /* TakeControl uses SD_VARLINK_METHOD_MORE so device events can be streamed back.
         * If the caller doesn't support streaming, just reply immediately. */
        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_reply(link, NULL);

        /* Don't reply yet — keep the connection open for device event notifications.
         * The reply will come when ReleaseControl is called or the connection drops. */
        return 0;
}

static int vl_method_release_control(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
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
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        if (!session_is_controller_varlink(session, link))
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);

        session_drop_controller(session);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_take_device(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                unsigned major, minor;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),    0                },
                { "Major", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,        voffsetof(p, major), SD_JSON_MANDATORY },
                { "Minor", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,        voffsetof(p, minor), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!DEVICE_MAJOR_VALID(p.major) || !DEVICE_MINOR_VALID(p.minor))
                return sd_varlink_error_invalid_parameter_name(link, "Major");

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        if (!SESSION_CLASS_CAN_TAKE_DEVICE(session->class))
                return sd_varlink_error_invalid_parameter_name(link, "Id");

        if (!session_is_controller_varlink(session, link))
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);

        dev_t dev = makedev(p.major, p.minor);
        _cleanup_(session_device_freep) SessionDevice *sd = NULL;

        sd = hashmap_get(session->devices, &dev);
        if (sd)
                return sd_varlink_error(link, "io.systemd.Login.DeviceIsTaken", NULL);

        r = session_device_new(session, dev, true, &sd);
        if (r < 0)
                return r;

        r = session_device_save(sd);
        if (r < 0)
                return r;

        r = sd_varlink_push_dup_fd(link, sd->fd);
        if (r < 0)
                return r;

        r = sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Inactive", !sd->active));
        if (r < 0)
                return r;

        session_save(session);
        TAKE_PTR(sd);

        return 1;
}

static int vl_method_release_device(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                unsigned major, minor;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),    0                },
                { "Major", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,        voffsetof(p, major), SD_JSON_MANDATORY },
                { "Minor", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,        voffsetof(p, minor), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!DEVICE_MAJOR_VALID(p.major) || !DEVICE_MINOR_VALID(p.minor))
                return sd_varlink_error_invalid_parameter_name(link, "Major");

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        if (!session_is_controller_varlink(session, link))
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);

        dev_t dev = makedev(p.major, p.minor);
        SessionDevice *sd = hashmap_get(session->devices, &dev);
        if (!sd)
                return sd_varlink_error(link, "io.systemd.Login.DeviceNotTaken", NULL);

        session_device_free(sd);
        session_save(session);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_pause_device_complete(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                unsigned major, minor;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",    SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, id),    0                },
                { "Major", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,        voffsetof(p, major), SD_JSON_MANDATORY },
                { "Minor", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint,        voffsetof(p, minor), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!DEVICE_MAJOR_VALID(p.major) || !DEVICE_MINOR_VALID(p.minor))
                return sd_varlink_error_invalid_parameter_name(link, "Major");

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        if (!session_is_controller_varlink(session, link))
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);

        dev_t dev = makedev(p.major, p.minor);
        SessionDevice *sd = hashmap_get(session->devices, &dev);
        if (!sd)
                return sd_varlink_error(link, "io.systemd.Login.DeviceNotTaken", NULL);

        session_device_complete_pause(sd);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_type(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                const char *type;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",   SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id),   0                },
                { "Type", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, type), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        SessionType type = session_type_from_string(p.type);
        if (type < 0)
                return sd_varlink_error_invalid_parameter_name(link, "Type");

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        if (!SESSION_CLASS_CAN_CHANGE_TYPE(session->class))
                return sd_varlink_error_invalid_parameter_name(link, "Type");

        if (!session_is_controller_varlink(session, link))
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);

        session_set_type(session, type);

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_display(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
                const char *display;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id",      SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id),      0                },
                { "Display", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, display), SD_JSON_MANDATORY },
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
                return r;

        if (!session_is_controller_varlink(session, link))
                return sd_varlink_error(link, "io.systemd.Login.NotInControl", NULL);

        if (!SESSION_TYPE_IS_GRAPHICAL(session->type))
                return sd_varlink_error_invalid_parameter_name(link, "Display");

        r = session_set_display(session, p.display);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_terminate_user(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                uid_t uid;
        } p = {
                .uid = UID_INVALID,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, voffsetof(p, uid), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        User *user;
        r = manager_varlink_get_user_by_uid(m, link, p.uid, &user);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        user->user_record->uid,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = user_stop(user, /* force= */ true);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_kill_user(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                uid_t uid;
                int signo;
        } p = {
                .uid = UID_INVALID,
                .signo = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, voffsetof(p, uid),   SD_JSON_MANDATORY },
                { "Signal", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_signal,  voffsetof(p, signo), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!SIGNAL_VALID(p.signo))
                return sd_varlink_error_invalid_parameter_name(link, "Signal");

        User *user;
        r = manager_varlink_get_user_by_uid(m, link, p.uid, &user);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        user->user_record->uid,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = user_kill(user, p.signo);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_user_linger(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                uid_t uid;
                int enable; /* tri-state */
        } p = {
                .uid = UID_INVALID,
                .enable = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid, voffsetof(p, uid),    0                },
                { "Enable", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate, voffsetof(p, enable), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        uid_t auth_uid;
        r = sd_varlink_get_peer_uid(link, &auth_uid);
        if (r < 0)
                return r;

        if (!uid_is_valid(p.uid)) {
                /* Resolve to the peer's owning UID */
                _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
                r = varlink_get_peer_pidref(link, &pidref);
                if (r < 0)
                        return r;

                r = cg_pidref_get_owner_uid(&pidref, &p.uid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get owner UID of peer: %m");
        }

        _cleanup_free_ struct passwd *pw = NULL;
        r = getpwuid_malloc(p.uid, &pw);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async_full(
                        link,
                        m->bus,
                        p.uid == auth_uid ? "org.freedesktop.login1.set-self-linger" :
                                            "org.freedesktop.login1.set-user-linger",
                        /* details= */ NULL,
                        /* good_user= */ UID_INVALID,
                        /* flags= */ 0,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        (void) mkdir_p_label("/var/lib/systemd", 0755);
        r = mkdir_safe_label("/var/lib/systemd/linger", 0755, 0, 0, MKDIR_WARN_MODE);
        if (r < 0)
                return r;

        _cleanup_free_ char *escaped = cescape(pw->pw_name);
        if (!escaped)
                return -ENOMEM;

        const char *path = strjoina("/var/lib/systemd/linger/", escaped);

        if (p.enable > 0) {
                r = touch(path);
                if (r < 0)
                        return r;

                User *u;
                if (manager_add_user_by_uid(m, p.uid, &u) >= 0) {
                        (void) user_send_changed(u, "Linger");
                        r = user_start(u);
                        if (r < 0) {
                                user_add_to_gc_queue(u);
                                return r;
                        }
                }
        } else {
                r = unlink(path);
                if (r < 0 && errno != ENOENT)
                        return -errno;

                User *u = hashmap_get(m->users, UID_TO_PTR(p.uid));
                if (u) {
                        u->gc_mode = USER_GC_BY_PIN;
                        user_add_to_gc_queue(u);
                        (void) user_send_changed(u, "Linger");
                }
        }

        return sd_varlink_reply(link, NULL);
}

static int vl_method_terminate_seat(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Seat *seat;
        r = manager_varlink_get_seat_by_name(m, link, p.id, &seat);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.manage",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = seat_stop_sessions(seat, /* force= */ true);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_activate_session_on_seat(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *session_id;
                const char *seat_id;
        } p;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "SessionId", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, session_id), SD_JSON_MANDATORY },
                { "SeatId",    SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, seat_id),    SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Session *session;
        r = manager_varlink_get_session_by_name(m, link, p.session_id, &session);
        if (r < 0)
                return r;

        Seat *seat;
        r = manager_varlink_get_seat_by_name(m, link, p.seat_id, &seat);
        if (r < 0)
                return r;

        if (session->seat != seat)
                return sd_varlink_error_invalid_parameter_name(link, "SessionId");

#if ENABLE_POLKIT
        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.chvt",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;
#endif

        r = session_activate(session);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_switch_to(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *seat_id;
                unsigned vtnr;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "SeatId", SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, voffsetof(p, seat_id), 0                },
                { "VTNr",   SD_JSON_VARIANT_UNSIGNED,  sd_json_dispatch_uint,         voffsetof(p, vtnr),    SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.vtnr <= 0)
                return sd_varlink_error_invalid_parameter_name(link, "VTNr");

        Seat *seat;
        r = manager_varlink_get_seat_by_name(m, link, p.seat_id, &seat);
        if (r < 0)
                return r;

#if ENABLE_POLKIT
        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.chvt",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;
#endif

        r = seat_switch_to(seat, p.vtnr);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_switch_to_next(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *seat_id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "SeatId", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, seat_id), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Seat *seat;
        r = manager_varlink_get_seat_by_name(m, link, p.seat_id, &seat);
        if (r < 0)
                return r;

#if ENABLE_POLKIT
        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.chvt",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;
#endif

        r = seat_switch_to_next(seat);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_switch_to_previous(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *seat_id;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "SeatId", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, seat_id), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        Seat *seat;
        r = manager_varlink_get_seat_by_name(m, link, p.seat_id, &seat);
        if (r < 0)
                return r;

#if ENABLE_POLKIT
        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.chvt",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;
#endif

        r = seat_switch_to_previous(seat);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int verify_shutdown_creds_varlink(
                Manager *m,
                sd_varlink *link,
                const HandleActionData *a,
                uint64_t flags) {

        /* Interactive polkit authorization is requested via the
         * "allowInteractiveAuthentication" JSON field on the incoming message and is
         * honored automatically by varlink_verify_polkit_async_full(), so no
         * POLKIT_ALLOW_INTERACTIVE needs to be plumbed through the flags here. */

        bool multiple_sessions, blocked;
        Inhibitor *offending = NULL;
        uid_t uid;
        int r;

        assert(m);
        assert(a);
        assert(link);

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        /* Check for other users' sessions */
        Session *session;
        multiple_sessions = false;
        HASHMAP_FOREACH(session, m->sessions)
                if (SESSION_CLASS_IS_INHIBITOR_LIKE(session->class) &&
                    session->user->user_record->uid != uid) {
                        multiple_sessions = true;
                        break;
                }

        blocked = manager_is_inhibited(m, a->inhibit_what, NULL, /* flags= */ 0, uid, &offending);

        if (multiple_sessions) {
                r = varlink_verify_polkit_async(
                                link,
                                m->bus,
                                a->polkit_action_multiple_sessions,
                                /* details= */ NULL,
                                &m->polkit_registry);
                if (r <= 0)
                        return r;
        }

        if (blocked) {
                if (!FLAGS_SET(flags, SD_LOGIND_SKIP_INHIBITORS) &&
                    (offending->mode != INHIBIT_BLOCK_WEAK ||
                     (uid == 0 && FLAGS_SET(flags, SD_LOGIND_ROOT_CHECK_INHIBITORS))))
                        return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

                PolkitFlags polkit_flags = 0;
                if (offending->mode != INHIBIT_BLOCK_WEAK)
                        polkit_flags |= POLKIT_ALWAYS_QUERY;

                r = varlink_verify_polkit_async_full(
                                link,
                                m->bus,
                                a->polkit_action_ignore_inhibit,
                                /* details= */ NULL,
                                /* good_user= */ UID_INVALID,
                                polkit_flags,
                                &m->polkit_registry);
                if (r <= 0)
                        return r;
        }

        if (!multiple_sessions && !blocked) {
                r = varlink_verify_polkit_async(
                                link,
                                m->bus,
                                a->polkit_action,
                                /* details= */ NULL,
                                &m->polkit_registry);
                if (r <= 0)
                        return r;
        }

        return 1; /* authorized */
}

static int vl_method_do_shutdown_or_sleep(
                sd_varlink *link,
                sd_json_variant *parameters,
                Manager *m,
                HandleAction action) {

        int r;

        struct {
                uint64_t flags;
        } p = {
                .flags = 0,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Flags", SD_JSON_VARIANT_UNSIGNED, sd_json_dispatch_uint64, voffsetof(p, flags), 0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if ((p.flags & ~SD_LOGIND_SHUTDOWN_AND_SLEEP_FLAGS_PUBLIC) != 0)
                return sd_varlink_error_invalid_parameter_name(link, "Flags");

        if (FLAGS_SET(p.flags, (SD_LOGIND_REBOOT_VIA_KEXEC|SD_LOGIND_SOFT_REBOOT)))
                return sd_varlink_error_invalid_parameter_name(link, "Flags");

        if (action != HANDLE_REBOOT) {
                if (FLAGS_SET(p.flags, SD_LOGIND_REBOOT_VIA_KEXEC))
                        return sd_varlink_error_invalid_parameter_name(link, "Flags");
                if (p.flags & (SD_LOGIND_SOFT_REBOOT|SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP))
                        return sd_varlink_error_invalid_parameter_name(link, "Flags");
        }

        const HandleActionData *a = NULL;

        if (FLAGS_SET(p.flags, SD_LOGIND_SOFT_REBOOT) ||
            (FLAGS_SET(p.flags, SD_LOGIND_SOFT_REBOOT_IF_NEXTROOT_SET_UP) && path_is_os_tree("/run/nextroot") > 0))
                a = handle_action_lookup(HANDLE_SOFT_REBOOT);
        else if (FLAGS_SET(p.flags, SD_LOGIND_REBOOT_VIA_KEXEC) && kexec_loaded())
                a = handle_action_lookup(HANDLE_KEXEC);

        if (action == HANDLE_SLEEP) {
                HandleAction selected = handle_action_sleep_select(m);
                if (selected < 0)
                        return sd_varlink_error_invalid_parameter_name(link, "Flags");

                assert_se(a = handle_action_lookup(selected));

        } else if (HANDLE_ACTION_IS_SLEEP(action)) {
                assert_se(a = handle_action_lookup(action));

                r = sleep_supported_full(a->sleep_operation, /* ret_support= */ NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_varlink_error_invalid_parameter_name(link, "Flags");
        } else if (!a)
                assert_se(a = handle_action_lookup(action));

        r = verify_shutdown_creds_varlink(m, link, a, p.flags);
        if (r <= 0)
                return r;

        if (m->delayed_action)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        m->unlink_nologin = false;
        reset_scheduled_shutdown(m);
        m->scheduled_shutdown_timeout = 0;
        m->scheduled_shutdown_action = action;

        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        r = bus_manager_shutdown_or_sleep_now_or_later(m, a, &error);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_poweroff(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_POWEROFF);
}

static int vl_method_login_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_REBOOT);
}

static int vl_method_login_halt(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_HALT);
}

static int vl_method_suspend(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_SUSPEND);
}

static int vl_method_hibernate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_HIBERNATE);
}

static int vl_method_hybrid_sleep(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_HYBRID_SLEEP);
}

static int vl_method_suspend_then_hibernate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_SUSPEND_THEN_HIBERNATE);
}

static int vl_method_sleep(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_do_shutdown_or_sleep(link, parameters, ASSERT_PTR(userdata), HANDLE_SLEEP);
}

static int vl_method_can_shutdown_or_sleep(sd_varlink *link, Manager *m, HandleAction action) {
        const HandleActionData *a;
        uid_t uid;
        int r;

        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        if (action == HANDLE_SLEEP) {
                HandleAction selected = handle_action_sleep_select(m);
                if (selected < 0)
                        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("Result", "na"));

                assert_se(a = handle_action_lookup(selected));

        } else if (HANDLE_ACTION_IS_SLEEP(action)) {
                assert_se(a = handle_action_lookup(action));

                r = sleep_supported_full(a->sleep_operation, /* ret_support= */ NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("Result", "na"));
        } else
                assert_se(a = handle_action_lookup(action));

        /* For Varlink, we do a simplified check: root gets "yes", non-root gets "challenge" if polkit
         * is available, "no" otherwise. This is a simplification — the D-Bus version does a detailed
         * non-interactive polkit probe which has no Varlink equivalent yet. */
        const char *result;
        if (uid == 0)
                result = "yes";
        else {
#if ENABLE_POLKIT
                result = "challenge";
#else
                result = "no";
#endif
        }

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("Result", result));
}

static int vl_method_can_poweroff(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_POWEROFF);
}

static int vl_method_can_reboot(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_REBOOT);
}

static int vl_method_can_halt(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_HALT);
}

static int vl_method_can_suspend(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_SUSPEND);
}

static int vl_method_can_hibernate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_HIBERNATE);
}

static int vl_method_can_hybrid_sleep(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_HYBRID_SLEEP);
}

static int vl_method_can_suspend_then_hibernate(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_SUSPEND_THEN_HIBERNATE);
}

static int vl_method_can_sleep(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        return vl_method_can_shutdown_or_sleep(link, ASSERT_PTR(userdata), HANDLE_SLEEP);
}

static int vl_method_schedule_shutdown(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *type;
                uint64_t usec;
        } p;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Type", SD_JSON_VARIANT_STRING,   sd_json_dispatch_const_string, voffsetof(p, type), SD_JSON_MANDATORY },
                { "USec", SD_JSON_VARIANT_UNSIGNED,  sd_json_dispatch_uint64,       voffsetof(p, usec), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        HandleAction handle = handle_action_from_string(p.type);
        if (!HANDLE_ACTION_IS_SHUTDOWN(handle))
                return sd_varlink_error_invalid_parameter_name(link, "Type");

        const HandleActionData *a;
        assert_se(a = handle_action_lookup(handle));

        r = verify_shutdown_creds_varlink(m, link, a, 0);
        if (r <= 0)
                return r;

        m->scheduled_shutdown_action = handle;
        m->shutdown_dry_run = false;
        m->scheduled_shutdown_timeout = p.usec;

        r = manager_setup_shutdown_timers(m);
        if (r < 0)
                return r;

        r = update_schedule_file(m);
        if (r < 0) {
                reset_scheduled_shutdown(m);
                return r;
        }

        manager_send_changed(m, "ScheduledShutdown");

        return sd_varlink_reply(link, NULL);
}

static int vl_method_cancel_scheduled_shutdown(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, NULL);
        if (r != 0)
                return r;

        bool cancelled = handle_action_valid(m->scheduled_shutdown_action) && m->scheduled_shutdown_action != HANDLE_IGNORE;
        if (!cancelled)
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Cancelled", false));

        const HandleActionData *a;
        assert_se(a = handle_action_lookup(m->scheduled_shutdown_action));

        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        a->polkit_action,
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        cancel_delayed_action(m);
        reset_scheduled_shutdown(m);

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Cancelled", true));
}

static const char* inhibit_what_polkit_action(InhibitWhat what, InhibitMode mode) {
        switch (what) {
        case INHIBIT_SHUTDOWN:
                return IN_SET(mode, INHIBIT_BLOCK, INHIBIT_BLOCK_WEAK) ?
                        "org.freedesktop.login1.inhibit-block-shutdown" :
                        "org.freedesktop.login1.inhibit-delay-shutdown";
        case INHIBIT_SLEEP:
                return IN_SET(mode, INHIBIT_BLOCK, INHIBIT_BLOCK_WEAK) ?
                        "org.freedesktop.login1.inhibit-block-sleep" :
                        "org.freedesktop.login1.inhibit-delay-sleep";
        case INHIBIT_IDLE:
                return "org.freedesktop.login1.inhibit-block-idle";
        case INHIBIT_HANDLE_POWER_KEY:
                return "org.freedesktop.login1.inhibit-handle-power-key";
        case INHIBIT_HANDLE_SUSPEND_KEY:
                return "org.freedesktop.login1.inhibit-handle-suspend-key";
        case INHIBIT_HANDLE_REBOOT_KEY:
                return "org.freedesktop.login1.inhibit-handle-reboot-key";
        case INHIBIT_HANDLE_HIBERNATE_KEY:
                return "org.freedesktop.login1.inhibit-handle-hibernate-key";
        case INHIBIT_HANDLE_LID_SWITCH:
                return "org.freedesktop.login1.inhibit-handle-lid-switch";
        default:
                return NULL;
        }
}

static int vl_method_inhibit(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *what;
                const char *who;
                const char *why;
                const char *mode;
        } p;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "What", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, what), SD_JSON_MANDATORY },
                { "Who",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, who),  SD_JSON_MANDATORY },
                { "Why",  SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, why),  SD_JSON_MANDATORY },
                { "Mode", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, mode), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        InhibitWhat w = inhibit_what_from_string(p.what);
        if (w <= 0)
                return sd_varlink_error_invalid_parameter_name(link, "What");

        InhibitMode mm = inhibit_mode_from_string(p.mode);
        if (mm < 0)
                return sd_varlink_error_invalid_parameter_name(link, "Mode");

        if (mm == INHIBIT_DELAY && (w & ~(INHIBIT_SHUTDOWN|INHIBIT_SLEEP)))
                return sd_varlink_error_invalid_parameter_name(link, "Mode");

        if (m->delayed_action && m->delayed_action->inhibit_what & w)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        BIT_FOREACH(i, w) {
                const InhibitWhat v = 1U << i;
                const char *action = inhibit_what_polkit_action(v, mm);

                r = varlink_verify_polkit_async(
                                link,
                                m->bus,
                                action,
                                /* details= */ NULL,
                                &m->polkit_registry);
                if (r <= 0)
                        return r;
        }

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        _cleanup_(pidref_done) PidRef pidref = PIDREF_NULL;
        r = varlink_get_peer_pidref(link, &pidref);
        if (r < 0)
                return r;

        if (hashmap_size(m->inhibitors) >= m->inhibitors_max)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, NULL);

        _cleanup_free_ char *id = NULL;
        do {
                id = mfree(id);
                if (asprintf(&id, "%" PRIu64, ++m->inhibit_counter) < 0)
                        return -ENOMEM;
        } while (hashmap_contains(m->inhibitors, id));

        _cleanup_(inhibitor_freep) Inhibitor *inhibitor = NULL;
        r = manager_add_inhibitor(m, id, &inhibitor);
        if (r < 0)
                return r;

        inhibitor->what = w;
        inhibitor->mode = mm;
        inhibitor->pid = TAKE_PIDREF(pidref);
        inhibitor->uid = uid;
        inhibitor->why = strdup(p.why);
        inhibitor->who = strdup(p.who);

        if (!inhibitor->why || !inhibitor->who)
                return -ENOMEM;

        _cleanup_close_ int fifo_fd = inhibitor_create_fifo(inhibitor);
        if (fifo_fd < 0)
                return fifo_fd;

        r = inhibitor_start(inhibitor);
        if (r < 0)
                return r;
        TAKE_PTR(inhibitor);

        r = sd_varlink_push_dup_fd(link, fifo_fd);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_set_reboot_parameter(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *parameter;
        } p;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Parameter", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, parameter), SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!reboot_parameter_is_valid(p.parameter))
                return sd_varlink_error_invalid_parameter_name(link, "Parameter");

        r = detect_container();
        if (r < 0)
                return r;
        if (r > 0)
                return sd_varlink_error_invalid_parameter_name(link, "Parameter");

        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.set-reboot-parameter",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = update_reboot_parameter_and_warn(p.parameter, /* keep= */ false);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_can_reboot_parameter(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        int r;

        r = detect_container();
        if (r < 0)
                return r;
        if (r > 0)
                return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("Result", "na"));

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        const char *result;
        if (uid == 0)
                result = "yes";
        else {
#if ENABLE_POLKIT
                result = "challenge";
#else
                result = "no";
#endif
        }

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_STRING("Result", result));
}

/* Determine whether booting into firmware setup is currently armed, mirroring the logic of
 * property_get_reboot_to_firmware_setup() in logind-dbus.c. Returns 1 if armed, 0 if not armed, or
 * a negative errno on failure / when the state cannot be determined. */
static int get_reboot_to_firmware_setup(void) {
        int r = getenv_bool("SYSTEMD_REBOOT_TO_FIRMWARE_SETUP");
        if (r == -ENXIO) {
                r = efi_get_reboot_to_firmware();
                if (r == -EOPNOTSUPP || r == -ENOENT)
                        return 0;
                return r;
        }
        if (r < 0)
                return r;
        if (r == 0)
                return 0;
        /* env=true non-EFI case: check /run marker */
        return access("/run/systemd/reboot-to-firmware-setup", F_OK) == 0;
}

/* Mirrors property_get_reboot_to_boot_loader_menu(). Returns the current timeout (or 0 with no
 * explicit timeout) via *ret, or -ENODATA if not armed / not supported. */
static int get_reboot_to_boot_loader_menu(uint64_t *ret) {
        assert(ret);

        int r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_MENU");
        if (r == -ENXIO) {
                usec_t x;
                r = efi_loader_get_config_timeout_one_shot(&x);
                if (r < 0)
                        return r == -ENOENT ? -ENODATA : r;
                *ret = x;
                return 0;
        }
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODATA;

        _cleanup_free_ char *v = NULL;
        r = read_one_line_file("/run/systemd/reboot-to-boot-loader-menu", &v);
        if (r < 0)
                return r == -ENOENT ? -ENODATA : r;
        return safe_atou64(v, ret);
}

/* Mirrors property_get_reboot_to_boot_loader_entry(). Returns a copy of the armed entry name via
 * *ret (caller frees), or -ENODATA if not armed / not supported. */
static int get_reboot_to_boot_loader_entry(Manager *m, char **ret) {
        assert(m);
        assert(ret);

        int r = getenv_bool("SYSTEMD_REBOOT_TO_BOOT_LOADER_ENTRY");
        if (r == -ENXIO) {
                r = efi_loader_update_entry_one_shot_cache(&m->efi_loader_entry_one_shot, &m->efi_loader_entry_one_shot_stat);
                if (r < 0)
                        return r == -ENOENT ? -ENODATA : r;
                if (!m->efi_loader_entry_one_shot)
                        return -ENODATA;
                char *c = strdup(m->efi_loader_entry_one_shot);
                if (!c)
                        return -ENOMEM;
                *ret = c;
                return 0;
        }
        if (r < 0)
                return r;
        if (r == 0)
                return -ENODATA;

        _cleanup_free_ char *v = NULL;
        r = read_one_line_file("/run/systemd/reboot-to-boot-loader-entry", &v);
        if (r < 0)
                return r == -ENOENT ? -ENODATA : r;
        if (!efi_loader_entry_name_valid(v))
                return -ENODATA;
        *ret = TAKE_PTR(v);
        return 0;
}

static int manager_build_json(Manager *m, sd_json_variant **ret) {
        assert(m);
        assert(ret);

        dual_timestamp idle_ts = DUAL_TIMESTAMP_NULL;
        int idle = manager_get_idle_hint(m, &idle_ts);

        bool preparing_for_shutdown = m->delayed_action && (m->delayed_action->inhibit_what & INHIBIT_SHUTDOWN);
        bool preparing_for_sleep = m->delayed_action && (m->delayed_action->inhibit_what & INHIBIT_SLEEP);

        _cleanup_free_ char *reboot_parameter = NULL;
        (void) read_reboot_parameter(&reboot_parameter);

        int firmware_setup = get_reboot_to_firmware_setup();

        uint64_t bootloader_menu = 0;
        int bootloader_menu_r = get_reboot_to_boot_loader_menu(&bootloader_menu);

        _cleanup_free_ char *bootloader_entry = NULL;
        (void) get_reboot_to_boot_loader_entry(m, &bootloader_entry);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_UNSIGNED("NAutoVTs", m->n_autovts),
                        SD_JSON_BUILD_PAIR_BOOLEAN("KillUserProcesses", m->kill_user_processes),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("KillOnlyUsers", m->kill_only_users),
                        JSON_BUILD_PAIR_STRV_NON_EMPTY("KillExcludeUsers", m->kill_exclude_users),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RebootParameter", reboot_parameter),
                        SD_JSON_BUILD_PAIR_BOOLEAN("IdleHint", idle > 0),
                        SD_JSON_BUILD_PAIR_CONDITION(idle > 0 && dual_timestamp_is_set(&idle_ts),
                                                     "IdleSinceHint", SD_JSON_BUILD_UNSIGNED(idle_ts.realtime)),
                        SD_JSON_BUILD_PAIR_CONDITION(idle > 0 && dual_timestamp_is_set(&idle_ts),
                                                     "IdleSinceHintMonotonic", SD_JSON_BUILD_UNSIGNED(idle_ts.monotonic)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("BlockInhibited",
                                                          inhibit_what_to_string(manager_inhibit_what(m, INHIBIT_BLOCK))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("BlockWeakInhibited",
                                                          inhibit_what_to_string(manager_inhibit_what(m, INHIBIT_BLOCK_WEAK))),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("DelayInhibited",
                                                          inhibit_what_to_string(manager_inhibit_what(m, INHIBIT_DELAY))),
                        SD_JSON_BUILD_PAIR_UNSIGNED("InhibitDelayMaxUSec", m->inhibit_delay_max),
                        SD_JSON_BUILD_PAIR_UNSIGNED("UserStopDelayUSec", m->user_stop_delay),
                        SD_JSON_BUILD_PAIR_STRING("HandlePowerKey", handle_action_to_string(m->handle_power_key)),
                        SD_JSON_BUILD_PAIR_STRING("HandlePowerKeyLongPress", handle_action_to_string(m->handle_power_key_long_press)),
                        SD_JSON_BUILD_PAIR_STRING("HandleRebootKey", handle_action_to_string(m->handle_reboot_key)),
                        SD_JSON_BUILD_PAIR_STRING("HandleRebootKeyLongPress", handle_action_to_string(m->handle_reboot_key_long_press)),
                        SD_JSON_BUILD_PAIR_STRING("HandleSuspendKey", handle_action_to_string(m->handle_suspend_key)),
                        SD_JSON_BUILD_PAIR_STRING("HandleSuspendKeyLongPress", handle_action_to_string(m->handle_suspend_key_long_press)),
                        SD_JSON_BUILD_PAIR_STRING("HandleHibernateKey", handle_action_to_string(m->handle_hibernate_key)),
                        SD_JSON_BUILD_PAIR_STRING("HandleHibernateKeyLongPress", handle_action_to_string(m->handle_hibernate_key_long_press)),
                        SD_JSON_BUILD_PAIR_STRING("HandleLidSwitch", handle_action_to_string(m->handle_lid_switch)),
                        SD_JSON_BUILD_PAIR_STRING("HandleLidSwitchExternalPower", handle_action_to_string(m->handle_lid_switch_ep)),
                        SD_JSON_BUILD_PAIR_STRING("HandleLidSwitchDocked", handle_action_to_string(m->handle_lid_switch_docked)),
                        SD_JSON_BUILD_PAIR_STRING("HandleSecureAttentionKey", handle_action_to_string(m->handle_secure_attention_key)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("HoldoffTimeoutUSec", m->holdoff_timeout_usec),
                        SD_JSON_BUILD_PAIR_STRING("IdleAction", handle_action_to_string(m->idle_action)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("IdleActionUSec", m->idle_action_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PreparingForShutdown", preparing_for_shutdown),
                        SD_JSON_BUILD_PAIR_BOOLEAN("PreparingForSleep", preparing_for_sleep),
                        SD_JSON_BUILD_PAIR("PreparingForShutdownWithMetadata",
                                           SD_JSON_BUILD_OBJECT(
                                                           SD_JSON_BUILD_PAIR_BOOLEAN("Preparing", preparing_for_shutdown),
                                                           SD_JSON_BUILD_PAIR_CONDITION(preparing_for_shutdown && m->delayed_action,
                                                                                        "Type",
                                                                                        SD_JSON_BUILD_STRING(preparing_for_shutdown && m->delayed_action ?
                                                                                                             handle_action_to_string(m->delayed_action->handle) : NULL)))),
                        SD_JSON_BUILD_PAIR_CONDITION(firmware_setup >= 0,
                                                     "RebootToFirmwareSetup",
                                                     SD_JSON_BUILD_BOOLEAN(firmware_setup > 0)),
                        SD_JSON_BUILD_PAIR_CONDITION(bootloader_menu_r >= 0,
                                                     "RebootToBootLoaderMenu",
                                                     SD_JSON_BUILD_UNSIGNED(bootloader_menu)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("RebootToBootLoaderEntry", bootloader_entry),
                        SD_JSON_BUILD_PAIR_CONDITION(handle_action_valid(m->scheduled_shutdown_action) &&
                                                     m->scheduled_shutdown_action != HANDLE_IGNORE,
                                                     "ScheduledShutdown",
                                                     SD_JSON_BUILD_OBJECT(
                                                                     SD_JSON_BUILD_PAIR_STRING("Type", handle_action_to_string(m->scheduled_shutdown_action)),
                                                                     SD_JSON_BUILD_PAIR_UNSIGNED("USec", m->scheduled_shutdown_timeout))),
                        SD_JSON_BUILD_PAIR_BOOLEAN("Docked", manager_is_docked_or_external_displays(m)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("LidClosed", manager_is_lid_closed(m)),
                        SD_JSON_BUILD_PAIR_BOOLEAN("OnExternalPower", manager_is_on_external_power()),
                        SD_JSON_BUILD_PAIR_BOOLEAN("RemoveIPC", m->remove_ipc),
                        SD_JSON_BUILD_PAIR_UNSIGNED("RuntimeDirectorySize", m->runtime_dir_size),
                        SD_JSON_BUILD_PAIR_UNSIGNED("RuntimeDirectoryInodesMax", m->runtime_dir_inodes),
                        SD_JSON_BUILD_PAIR_UNSIGNED("InhibitorsMax", m->inhibitors_max),
                        SD_JSON_BUILD_PAIR_UNSIGNED("NCurrentInhibitors", (uint64_t) hashmap_size(m->inhibitors)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("SessionsMax", m->sessions_max),
                        SD_JSON_BUILD_PAIR_UNSIGNED("NCurrentSessions", (uint64_t) hashmap_size(m->sessions)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("StopIdleSessionUSec", m->stop_idle_session_usec),
                        SD_JSON_BUILD_PAIR_BOOLEAN("EnableWallMessages", m->wall_messages),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("WallMessage", m->wall_message));
}

static int vl_method_describe_manager(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        r = manager_build_json(m, &v);
        if (r < 0)
                return r;

        return sd_varlink_replybo(link, SD_JSON_BUILD_PAIR_VARIANT("Manager", v));
}

#define WALL_MESSAGE_MAX 4096U

static int vl_method_set_wall_message(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *wall_message;
                int enable; /* tri-state */
        } p = {
                .enable = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "WallMessage", SD_JSON_VARIANT_STRING,  sd_json_dispatch_const_string, voffsetof(p, wall_message), 0                },
                { "Enable",      SD_JSON_VARIANT_BOOLEAN, sd_json_dispatch_tristate,     voffsetof(p, enable),       SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (p.wall_message && strlen(p.wall_message) > WALL_MESSAGE_MAX)
                return sd_varlink_error_invalid_parameter_name(link, "WallMessage");

        if (streq_ptr(m->wall_message, empty_to_null(p.wall_message)) &&
            m->wall_messages == (p.enable > 0))
                return sd_varlink_reply(link, NULL);

        r = varlink_verify_polkit_async(
                        link,
                        m->bus,
                        "org.freedesktop.login1.set-wall-message",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        r = free_and_strdup(&m->wall_message, empty_to_null(p.wall_message));
        if (r < 0)
                return log_oom();

        m->wall_messages = p.enable > 0;

        return sd_varlink_reply(link, NULL);
}

static int vl_method_subscribe_manager_events(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

        /* Emit an initial snapshot of the current session/user/seat set so the client
         * doesn't need a separate ListX call to learn about pre-existing objects. We do
         * this synchronously before registering the subscription, so the client receives
         * a well-ordered stream: snapshot events first, then Ready, then live events. */
        Session *session;
        HASHMAP_FOREACH(session, m->sessions) {
                r = sd_varlink_notifybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("Event", "SessionNew"),
                                SD_JSON_BUILD_PAIR("Data",
                                                   SD_JSON_BUILD_OBJECT(
                                                                   SD_JSON_BUILD_PAIR_STRING("Id", session->id))));
                if (r < 0)
                        return r;
        }

        User *user;
        HASHMAP_FOREACH(user, m->users) {
                r = sd_varlink_notifybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("Event", "UserNew"),
                                SD_JSON_BUILD_PAIR("Data",
                                                   SD_JSON_BUILD_OBJECT(
                                                                   SD_JSON_BUILD_PAIR_UNSIGNED("UID", user->user_record->uid))));
                if (r < 0)
                        return r;
        }

        Seat *seat;
        HASHMAP_FOREACH(seat, m->seats) {
                r = sd_varlink_notifybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("Event", "SeatNew"),
                                SD_JSON_BUILD_PAIR("Data",
                                                   SD_JSON_BUILD_OBJECT(
                                                                   SD_JSON_BUILD_PAIR_STRING("Id", seat->id))));
                if (r < 0)
                        return r;
        }

        /* Signal end of snapshot / start of live events. */
        r = sd_varlink_notifybo(link, SD_JSON_BUILD_PAIR_BOOLEAN("Ready", true));
        if (r < 0)
                return r;

        r = set_ensure_put(&m->varlink_manager_subscriptions, NULL, link);
        if (r < 0)
                return r;
        if (r > 0)
                sd_varlink_ref(link);

        return 1;
}

int manager_varlink_notify_manager_event(Manager *m, const char *event, sd_json_variant *data) {
        assert(m);
        assert(event);

        if (set_isempty(m->varlink_manager_subscriptions))
                return 0;

        sd_varlink *link;
        SET_FOREACH(link, m->varlink_manager_subscriptions) {
                int r = sd_varlink_notifybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("Event", event),
                                SD_JSON_BUILD_PAIR_CONDITION(data != NULL, "Data", SD_JSON_BUILD_VARIANT(data)));
                if (r < 0)
                        log_debug_errno(r, "Failed to send manager event notification, ignoring: %m");
        }

        return 0;
}

static void vl_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        sd_varlink *removed_link;

        assert(server);
        assert(link);

        /* When a Varlink connection disconnects, check if it was a session controller and drop it */
        Session *session;
        HASHMAP_FOREACH(session, m->sessions)
                if (session_is_controller_varlink(session, link)) {
                        session_drop_controller(session);
                        break;
                }

        /* Clean up manager event subscriptions */
        removed_link = set_remove(m->varlink_manager_subscriptions, link);
        if (removed_link)
                sd_varlink_unref(removed_link);
}

static int vl_method_list_inhibitors(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        if (!FLAGS_SET(flags, SD_VARLINK_METHOD_MORE))
                return sd_varlink_error(link, SD_VARLINK_ERROR_EXPECTED_MORE, /* parameters= */ NULL);

        r = sd_varlink_dispatch(link, parameters, /* dispatch_table= */ NULL, /* userdata= */ NULL);
        if (r != 0)
                return r;

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
        r = manager_varlink_get_session_by_name(m, link, p.id, &session);
        if (r < 0)
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
                        "io.systemd.Login.DescribeSession",  vl_method_describe_session,
                        "io.systemd.Login.ListSessions",     vl_method_list_sessions,
                        "io.systemd.Login.DescribeUser",     vl_method_describe_user,
                        "io.systemd.Login.ListUsers",        vl_method_list_users,
                        "io.systemd.Login.DescribeSeat",     vl_method_describe_seat,
                        "io.systemd.Login.ListSeats",        vl_method_list_seats,
                        "io.systemd.Login.ListInhibitors",   vl_method_list_inhibitors,
                        "io.systemd.Login.ActivateSession",  vl_method_activate_session,
                        "io.systemd.Login.LockSession",      vl_method_lock_session,
                        "io.systemd.Login.UnlockSession",    vl_method_unlock_session,
                        "io.systemd.Login.TerminateSession", vl_method_terminate_session,
                        "io.systemd.Login.KillSession",      vl_method_kill_session,
                        "io.systemd.Login.SetIdleHint",      vl_method_set_idle_hint,
                        "io.systemd.Login.SetLockedHint",    vl_method_set_locked_hint,
                        "io.systemd.Login.TakeControl",      vl_method_take_control,
                        "io.systemd.Login.ReleaseControl",   vl_method_release_control,
                        "io.systemd.Login.TakeDevice",       vl_method_take_device,
                        "io.systemd.Login.ReleaseDevice",    vl_method_release_device,
                        "io.systemd.Login.PauseDeviceComplete", vl_method_pause_device_complete,
                        "io.systemd.Login.SetType",          vl_method_set_type,
                        "io.systemd.Login.SetDisplay",       vl_method_set_display,
                        "io.systemd.Login.TerminateUser",    vl_method_terminate_user,
                        "io.systemd.Login.KillUser",         vl_method_kill_user,
                        "io.systemd.Login.SetUserLinger",    vl_method_set_user_linger,
                        "io.systemd.Login.TerminateSeat",    vl_method_terminate_seat,
                        "io.systemd.Login.ActivateSessionOnSeat", vl_method_activate_session_on_seat,
                        "io.systemd.Login.SwitchTo",         vl_method_switch_to,
                        "io.systemd.Login.SwitchToNext",     vl_method_switch_to_next,
                        "io.systemd.Login.SwitchToPrevious", vl_method_switch_to_previous,
                        "io.systemd.Login.PowerOff",         vl_method_poweroff,
                        "io.systemd.Login.Reboot",           vl_method_login_reboot,
                        "io.systemd.Login.Halt",             vl_method_login_halt,
                        "io.systemd.Login.Suspend",          vl_method_suspend,
                        "io.systemd.Login.Hibernate",        vl_method_hibernate,
                        "io.systemd.Login.HybridSleep",      vl_method_hybrid_sleep,
                        "io.systemd.Login.SuspendThenHibernate", vl_method_suspend_then_hibernate,
                        "io.systemd.Login.Sleep",            vl_method_sleep,
                        "io.systemd.Login.CanPowerOff",      vl_method_can_poweroff,
                        "io.systemd.Login.CanReboot",        vl_method_can_reboot,
                        "io.systemd.Login.CanHalt",          vl_method_can_halt,
                        "io.systemd.Login.CanSuspend",       vl_method_can_suspend,
                        "io.systemd.Login.CanHibernate",     vl_method_can_hibernate,
                        "io.systemd.Login.CanHybridSleep",   vl_method_can_hybrid_sleep,
                        "io.systemd.Login.CanSuspendThenHibernate", vl_method_can_suspend_then_hibernate,
                        "io.systemd.Login.CanSleep",         vl_method_can_sleep,
                        "io.systemd.Login.ScheduleShutdown", vl_method_schedule_shutdown,
                        "io.systemd.Login.CancelScheduledShutdown", vl_method_cancel_scheduled_shutdown,
                        "io.systemd.Login.Inhibit",          vl_method_inhibit,
                        "io.systemd.Login.SetRebootParameter", vl_method_set_reboot_parameter,
                        "io.systemd.Login.CanRebootParameter", vl_method_can_reboot_parameter,
                        "io.systemd.Login.SetWallMessage",   vl_method_set_wall_message,
                        "io.systemd.Login.DescribeManager",  vl_method_describe_manager,
                        "io.systemd.Login.SubscribeManagerEvents", vl_method_subscribe_manager_events,
                        "io.systemd.Login.ListInhibitors",   vl_method_list_inhibitors,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = sd_varlink_server_bind_disconnect(s, vl_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink disconnect handler: %m");

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

        m->varlink_manager_subscriptions = set_free(m->varlink_manager_subscriptions);
        m->varlink_server = sd_varlink_server_unref(m->varlink_server);
}
