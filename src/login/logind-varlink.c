/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup-util.h"
#include "fd-util.h"
#include "json-util.h"
#include "logind.h"
#include "logind-dbus.h"
#include "logind-session-dbus.h"
#include "logind-varlink.h"
#include "terminal-util.h"
#include "user-util.h"
#include "varlink-io.systemd.Login.h"
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
         * true, then will return the display session of the peer's owning user */

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

        if (!session)
                return sd_varlink_error(link, "io.systemd.Login.NoSuchSession", /* parameters= */ NULL);

        *ret = session;
        return 0;
}

static int manager_varlink_get_session_by_name(
                Manager *m,
                sd_varlink *link,
                const char *name,
                Session **ret) {

        assert(m);
        assert(link);
        assert(ret);

        /* Resolves a session name to a session object. Supports resolving the special names "self" and "auto". */

        if (SESSION_IS_SELF(name))
                return manager_varlink_get_session_by_peer(m, link, /* consult_display= */ false, ret);
        if (SESSION_IS_AUTO(name))
                return manager_varlink_get_session_by_peer(m, link, /* consult_display= */ true, ret);

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

        _cleanup_close_ int fifo_fd = session_create_fifo(s);
        if (fifo_fd < 0)
                return fifo_fd;

        /* Update the session state file before we notify the client about the result. */
        session_save(s);

        log_debug("Sending Varlink reply about created session: "
                  "id=%s uid=" UID_FMT " runtime_path=%s "
                  "session_fd=%d seat=%s vtnr=%u",
                  s->id,
                  s->user->user_record->uid,
                  s->user->runtime_path,
                  fifo_fd,
                  s->seat ? s->seat->id : "",
                  s->vtnr);

        int fifo_fd_idx = sd_varlink_push_fd(vl, fifo_fd);
        if (fifo_fd_idx < 0) {
                log_error_errno(fifo_fd_idx, "Failed to push FIFO fd to Varlink: %m");
                return sd_varlink_error_errno(vl, fifo_fd_idx);
        }

        TAKE_FD(fifo_fd);

        return sd_varlink_replybo(
                        vl,
                        SD_JSON_BUILD_PAIR_STRING("Id", s->id),
                        SD_JSON_BUILD_PAIR_STRING("RuntimePath", s->user->runtime_path),
                        SD_JSON_BUILD_PAIR_UNSIGNED("SessionFileDescriptor", fifo_fd_idx),
                        SD_JSON_BUILD_PAIR_UNSIGNED("UID", s->user->user_record->uid),
                        SD_JSON_BUILD_PAIR_CONDITION(!!s->seat, "Seat", SD_JSON_BUILD_STRING(s->seat ? s->seat->id : NULL)),
                        SD_JSON_BUILD_PAIR_CONDITION(s->vtnr > 0, "VTNr", SD_JSON_BUILD_UNSIGNED(s->vtnr)),
                        SD_JSON_BUILD_PAIR_STRING("Class", session_class_to_string(s->class)),
                        SD_JSON_BUILD_PAIR_STRING("Type", session_type_to_string(s->type)));
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
} CreateSessionParameters;

static void create_session_parameters_done(CreateSessionParameters *p) {
        pidref_done(&p->pid);
}

static int vl_method_create_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "UID",        _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,      offsetof(CreateSessionParameters, uid),         SD_JSON_MANDATORY },
                { "PID",        _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_pidref,          offsetof(CreateSessionParameters, pid),         SD_JSON_RELAX     },
                { "Service",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, service),     0                 },
                { "Type",       SD_JSON_VARIANT_STRING,        json_dispatch_session_type,    offsetof(CreateSessionParameters, type),        SD_JSON_MANDATORY },
                { "Class",      SD_JSON_VARIANT_STRING,        json_dispatch_session_class,   offsetof(CreateSessionParameters, class),       SD_JSON_MANDATORY },
                { "Desktop",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, desktop),     SD_JSON_STRICT    },
                { "Seat",       SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, seat),        0                 },
                { "VTNr",       _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         offsetof(CreateSessionParameters, vtnr),        0                 },
                { "TTY",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, tty),         0                 },
                { "Display",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, display),     0                 },
                { "Remote",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(CreateSessionParameters, remote),      0                 },
                { "RemoteUser", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, remote_user), 0                 },
                { "RemoteHost", SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(CreateSessionParameters, remote_host), 0                 },
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
        uid_t peer_uid;
        r = sd_varlink_get_peer_uid(link, &peer_uid);
        if (r < 0)
                return log_debug_errno(r, "Failed to get peer UID: %m");
        if (peer_uid != 0)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        if (!pidref_is_set(&p.pid)) {
                r = varlink_get_peer_pidref(link, &p.pid);
                if (r < 0)
                        return log_debug_errno(r, "Failed to get peer pidref: %m");
        }

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

static int vl_method_release_session(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        struct {
                const char *id;
        } p;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "Id", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, id), SD_JSON_MANDATORY },
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

        if (session != peer_session)
                return sd_varlink_error(link, SD_VARLINK_ERROR_PERMISSION_DENIED, /* parameters= */ NULL);

        r = session_release(session);
        if (r < 0)
                return r;

        return sd_varlink_reply(link, NULL);
}

int manager_varlink_init(Manager *m) {
        _cleanup_(sd_varlink_server_unrefp) sd_varlink_server *s = NULL;
        int r;

        assert(m);

        if (m->varlink_server)
                return 0;

        r = sd_varlink_server_new(
                        &s,
                        SD_VARLINK_SERVER_ACCOUNT_UID|
                        SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate varlink server object: %m");

        sd_varlink_server_set_userdata(s, m);

        r = sd_varlink_server_add_interface_many(
                        s,
                        &vl_interface_io_systemd_Login,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add Login interface to varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        s,
                        "io.systemd.Login.CreateSession",    vl_method_create_session,
                        "io.systemd.Login.ReleaseSession",   vl_method_release_session,
                        "io.systemd.service.Ping",           varlink_method_ping,
                        "io.systemd.service.SetLogLevel",    varlink_method_set_log_level,
                        "io.systemd.service.GetEnvironment", varlink_method_get_environment);
        if (r < 0)
                return log_error_errno(r, "Failed to register varlink methods: %m");

        r = sd_varlink_server_listen_address(s, "/run/systemd/io.systemd.Login", 0666);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to varlink socket: %m");

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
