/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <paths.h>
#include <sys/stat.h>

#include "sd-event.h"
#include "sd-id128.h"
#include "sd-json.h"
#include "sd-varlink.h"

#include "alloc-util.h"
#include "bus-polkit.h"
#include "common-signal.h"
#include "daemon-util.h"
#include "env-util.h"
#include "event-util.h"
#include "fd-util.h"
#include "hashmap.h"
#include "log.h"
#include "macro.h"
#include "main-func.h"
#include "path-lookup.h"
#include "path-util.h"
#include "runtime-scope.h"
#include "service-util.h"
#include "terminal-util.h"
#include "time-util.h"
#include "varlink-io.systemd.service.h"
#include "varlink-io.systemd.PTYBroker.h"
#include "varlink-util.h"
#include "json-util.h"
#include "set.h"
#include "ptybroker.h"
#include "ptybroker-pty.h"
#include "ptybroker-monitor.h"
#include "strv.h"

// TODO:
// - strip ansi doesn't work
// - vmspawn: "headless with broker" mode
// - size change events
// - maybe dlopen() libtsm one day, to maintain framebuffer of console context and provide that instead of scrollback buffer

#define PSEUDO_TTY_MAX 1024U
#define MONITOR_MAX 16U

static Manager* manager_free(Manager *m) {
        if (!m)
                return NULL;

        hashmap_free(m->ptys);
        assert(!m->ptys_free_queue);

        sd_varlink_server_unref(m->varlink_server);
        hashmap_free(m->polkit_registry);

        sd_event_source_disable_unref(m->ptys_free_queue_event_source);
        sd_event_source_disable_unref(m->exit_on_idle_event_source);
        sd_event_unref(m->event);

        return mfree(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Manager*, manager_free);

static int start_shell(
                Manager *m,
                PseudoTTY *pty,
                const char *user,
                const char *group,
                const char *working_directory,
                char **environment,
                int lightweight,
                int backend_fd,
                const char *backend_path) {

        int r;

        assert(m);
        assert(pty);
        assert(backend_fd >= 0);
        assert(backend_path);

        const char *d;
        _cleanup_free_ char *description = NULL;
        if (user) {
                description = strjoin("Shell of '", user, "'");
                if (!description)
                        return log_oom();

                d = description;
        } else
                d = "Shell";

        _cleanup_free_ char *unit = strjoin("shell-", pty->name, ".service");
        if (!unit)
                return log_oom();

        _cleanup_strv_free_ char **patched_environment = NULL;
        if (!strv_env_get(environment, "XDG_SESSION_CLASS") && lightweight >= 0) {
                const char *class = NULL;

                bool is_root = STRPTR_IN_SET(user, "root", "0") || (!user && m->scope == RUNTIME_SCOPE_SYSTEM);

                if (lightweight >= 0) {
                        class = lightweight ? (is_root ? "user-early-light" : "user-light") :
                                              (is_root ? "user-early" : "user");

                        log_debug("Setting XDG_SESSION_CLASS to '%s'.", class);

                        patched_environment = strv_copy(environment);
                        if (!patched_environment)
                                return log_oom();

                        r = strv_env_assign(&patched_environment, "XDG_SESSION_CLASS", class);
                        if (r < 0)
                                return log_error_errno(r, "Failed to set $XDG_SESSION_CLASS environment variable: %m");

                        environment = patched_environment;
                }
        }

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(m->scope, "systemd/io.systemd.Manager", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine service manager socket path: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to service manager Varlink socket: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable fd passing to Varlink socket: %m");

        int fd_stdin_idx = sd_varlink_push_dup_fd(vl, pty->backend_fd);
        if (fd_stdin_idx < 0)
                return log_error_errno(fd_stdin_idx, "Failed to push file descriptor into Varlink connection: %m");

        int fd_stdout_idx = sd_varlink_push_dup_fd(vl, pty->backend_fd);
        if (fd_stdout_idx < 0)
                return log_error_errno(fd_stdout_idx, "Failed to push file descriptor into Varlink connection: %m");

        int fd_stderr_idx = sd_varlink_push_fd(vl, pty->backend_fd);
        if (fd_stderr_idx < 0)
                return log_error_errno(fd_stderr_idx, "Failed to push file descriptor into Varlink connection: %m");

        TAKE_FD(pty->backend_fd);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_callbo(
                        vl,
                        "io.systemd.Unit.StartTransient",
                        &reply,
                        &error_id,
                        SD_JSON_BUILD_PAIR("context", SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("ID", unit),
                                        SD_JSON_BUILD_PAIR_STRING("Description", d),
                                        SD_JSON_BUILD_PAIR_STRING("CollectMode", "inactive_or_failed"),
                                        SD_JSON_BUILD_PAIR("Kill", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_BOOLEAN("SendSIGHUP", true))),
                                        SD_JSON_BUILD_PAIR("Service", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_STRING("Type", "exec"),
                                                                           SD_JSON_BUILD_PAIR_INTEGER("StandardInputFileDescriptor", fd_stdin_idx),
                                                                           SD_JSON_BUILD_PAIR_INTEGER("StandardOutputFileDescriptor", fd_stdout_idx),
                                                                           SD_JSON_BUILD_PAIR_INTEGER("StandardErrorFileDescriptor", fd_stderr_idx),
                                                                           SD_JSON_BUILD_PAIR("ExecStart", SD_JSON_BUILD_ARRAY(
                                                                                                              SD_JSON_BUILD_OBJECT(
                                                                                                                              SD_JSON_BUILD_PAIR_STRING("path", _PATH_BSHELL),
                                                                                                                              SD_JSON_BUILD_PAIR("arguments", SD_JSON_BUILD_ARRAY(
                                                                                                                                                                 SD_JSON_BUILD_STRING("-" _PATH_BSHELL)))))))),
                                        SD_JSON_BUILD_PAIR("Exec", SD_JSON_BUILD_OBJECT(
                                                                           SD_JSON_BUILD_PAIR_STRING("TTYPath", backend_path),
                                                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("User", user),
                                                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("Group", group),
                                                                           JSON_BUILD_PAIR_STRING_NON_EMPTY("WorkingDirectory", working_directory),
                                                                           JSON_BUILD_PAIR_STRV_NON_EMPTY("Environment", environment),
                                                                           SD_JSON_BUILD_PAIR_BOOLEAN("IgnoreSIGPIPE", false))))),
                        SD_JSON_BUILD_PAIR_STRING("mode", "replace"));
        if (r < 0)
                return log_error_errno(r, "Failed to call io.systemd.Unit.StartTransient: %m");
        if (error_id)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTO),
                                       "io.systemd.Unit.StartTransient failed: %s", error_id);

        return 0;
}

typedef struct AcquirePtyParameters {
        FrontendType frontend_type;
        BackendType backend_type;
        char *name;
        char *description;
        char *tag;
        const char *user;
        const char *group;
        const char *working_directory;
        char **environment;
        int lightweight;
        int monitor;
        bool hang_up_on_disconnect;
        sd_json_variant *terminal_settings; /* no reference */
} AcquirePtyParameters;

static void acquire_pty_parameters_done(AcquirePtyParameters *p) {
        assert(p);

        free(p->name);
        free(p->description);
        free(p->tag);
        strv_free(p->environment);
}

static JSON_DISPATCH_ENUM_DEFINE(dispatch_frontend_type, FrontendType, frontend_type_from_string);
static JSON_DISPATCH_ENUM_DEFINE(dispatch_backend_type, BackendType, backend_type_from_string);

static int vl_method_acquire_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        _cleanup_(acquire_pty_parameters_done) AcquirePtyParameters p = {
                .frontend_type = _FRONTEND_TYPE_INVALID,
                .backend_type = _BACKEND_TYPE_INVALID,
                .lightweight = -1,
                .monitor = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "frontendType",       _SD_JSON_VARIANT_TYPE_INVALID, dispatch_frontend_type,              voffsetof(p, frontend_type),         SD_JSON_MANDATORY },
                { "backendType",        _SD_JSON_VARIANT_TYPE_INVALID, dispatch_backend_type,               voffsetof(p, backend_type),          SD_JSON_MANDATORY },
                { "name",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, name),                  0                 },
                { "description",        SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, description),           0                 },
                { "tag",                SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,             voffsetof(p, tag),                   0                 },
                { "user",               SD_JSON_VARIANT_STRING,        json_dispatch_const_user_group_name, voffsetof(p, user),                  0                 },
                { "group",              SD_JSON_VARIANT_STRING,        json_dispatch_const_user_group_name, voffsetof(p, group),                 0                 },
                { "workingDirectory",   SD_JSON_VARIANT_STRING,        json_dispatch_const_path,            voffsetof(p, working_directory),     0                 },
                { "environment",        _SD_JSON_VARIANT_TYPE_INVALID, json_dispatch_strv_environment,      voffsetof(p, environment),           0                 },
                { "lightweight",        SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,           voffsetof(p, lightweight),           0                 },
                { "monitor",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,           voffsetof(p, monitor),               0                 },
                { "hangUpOnDisconnect", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,            voffsetof(p, hang_up_on_disconnect), 0                 },
                { "terminalSettings",   SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref,      voffsetof(p, terminal_settings),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.acquire-pty",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        uid_t uid;
        r = sd_varlink_get_peer_uid(link, &uid);
        if (r < 0)
                return r;

        gid_t gid;
        r = sd_varlink_get_peer_gid(link, &gid);
        if (r < 0)
                return r;

        if (p.name) {
                if (!pseudo_tty_name_valid(p.name))
                        return sd_varlink_error_invalid_parameter_name(link, "name");

                if (hashmap_get(m->ptys, p.name))
                        return sd_varlink_error(link, "io.systemd.PTYBroker.PtyExists", NULL);
        } else {
                sd_id128_t id;

                r = sd_id128_randomize(&id);
                if (r < 0)
                        return r;

                p.name = strdup(SD_ID128_TO_STRING(id));
                if (!p.name)
                        return log_oom();
        }

        if (p.description && !pseudo_tty_description_valid(p.description))
                return sd_varlink_error_invalid_parameter_name(link, "description");

        if (p.tag && !pseudo_tty_tag_valid(p.tag))
                return sd_varlink_error_invalid_parameter_name(link, "tag");

        if (p.monitor >= 0 && p.frontend_type == FRONTEND_TAKE)
                return sd_varlink_error_invalid_parameter_name(link, "monitor");

        if (p.backend_type != BACKEND_SHELL) {
                if (p.user)
                        return sd_varlink_error_invalid_parameter_name(link, "user");
                if (p.group)
                        return sd_varlink_error_invalid_parameter_name(link, "group");
                if (p.working_directory)
                        return sd_varlink_error_invalid_parameter_name(link, "directory");
                if (!strv_isempty(p.environment))
                        return sd_varlink_error_invalid_parameter_name(link, "environment");
                if (p.lightweight >= 0)
                        return sd_varlink_error_invalid_parameter_name(link, "lightweight");
        }

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        r = terminal_settings_settle(&ts);
        if (r < 0)
                return r;

        if (hashmap_size(m->ptys) >= PSEUDO_TTY_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyPtys", NULL);

        _cleanup_(pseudo_tty_freep) PseudoTTY *pty = NULL;
        r = pseudo_tty_new(&pty);
        if (r < 0)
                return r;

        pty->frontend_fd = openpt_allocate(O_RDWR|O_NOCTTY|O_CLOEXEC, &pty->backend_path);
        if (pty->frontend_fd < 0)
                return log_error_errno(pty->frontend_fd, "Failed to allocate PTY: %m");

        pty->backend_fd = pty_open_peer(pty->frontend_fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (pty->backend_fd < 0)
                return log_error_errno(pty->backend_fd, "Failed to open PTY backend: %m");

        pty->pin_fd = fd_reopen(pty->backend_fd, O_PATH|O_CLOEXEC);
        if (pty->pin_fd < 0)
                return log_error_errno(pty->pin_fd, "Failed to open O_PATH fd on backend: %m");

        /* First set what is requested */
        r = terminal_set_size_fd(pty->frontend_fd, pty->backend_path, ts.lines, ts.columns);
        if (r < 0)
                return log_error_errno(r, "Failed to set PTY dimensions: %m");

        pty->name = TAKE_PTR(p.name);
        pty->description = TAKE_PTR(p.description);
        pty->tag = TAKE_PTR(p.tag);
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(ts);
        pty->frontend_type = p.frontend_type;
        pty->backend_type = p.backend_type;

        /* Read back the settled terminal settings while the frontend fd is still open — for the
         * FRONTEND_TAKE case we close it below before handing it to the client, and would then no longer be
         * able to query the dimensions. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return r;

        int frontend_idx = -EINVAL;
        if (pty->frontend_type == FRONTEND_TAKE) {
                if (fchown(pty->frontend_fd, uid, gid) < 0)
                        return log_error_errno(errno, "Failed to adjust ownership of PTY frontend to client's UID/GID: %m");

                frontend_idx = sd_varlink_push_fd(link, pty->frontend_fd);
                if (frontend_idx < 0)
                        return log_error_errno(frontend_idx, "Failed to push PTY frontend fd to client: %m");

                TAKE_FD(pty->frontend_fd);
        }

        int backend_idx = -EINVAL;
        if (pty->backend_type == BACKEND_TAKE) {
                assert(pty->backend_fd >= 0);

                if (fchown(pty->backend_fd, uid, gid) < 0)
                        return log_error_errno(errno, "Failed to adjust ownership of PTY backend to client's UID/GID: %m");

                backend_idx = sd_varlink_push_fd(link, pty->backend_fd);
                if (backend_idx < 0)
                        return log_error_errno(backend_idx, "Failed to push PTY backend fd to client: %m");

                TAKE_FD(pty->backend_fd);
        }

        if (pty->backend_type == BACKEND_SHELL) {
                assert(pty->backend_fd >= 0);

                r = start_shell(m,
                                pty,
                                p.user,
                                p.group,
                                p.working_directory,
                                p.environment,
                                p.lightweight,
                                pty->backend_fd,
                                pty->backend_path);
                if (r < 0)
                        return r;
        }

        r = pseudo_tty_watch_frontend_fd(pty, m->event);
        if (r < 0)
                return r;

        /* Also watch the backend device node for removal. For FRONTEND_TAKE we handed the frontend fd to the
         * client and no longer hold one to watch for EPOLLHUP, so this is how we learn the PTY is gone. */
        r = pseudo_tty_watch_backend_node(pty, m->event);
        if (r < 0)
                return r;

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = NULL;
        if (p.monitor > 0) {
                assert(pty->frontend_fd >= 0);

                r = pseudo_tty_monitor_new(link, &monitor);
                if (r < 0)
                        return log_oom();

                monitor->hang_up_on_disconnect = p.hang_up_on_disconnect;
        }

        /* Link everything into the manager *before* sending the (upgrade) response: once the upgrade reply
         * is enqueued the upgrade callback may fire, and it requires the monitor to be fully wired up (in
         * particular its connection userdata pointer). Doing all fallible linking up front also ensures we
         * never leave a connection half-upgraded if e.g. the hashmap insertion runs out of memory. */
        r = pseudo_tty_link(pty, m);
        if (r < 0)
                return r;

        if (monitor)
                pseudo_tty_monitor_link(monitor, pty);

        if (p.monitor > 0)
                r = sd_varlink_respond_and_upgradebo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                                SD_JSON_BUILD_PAIR_CONDITION(backend_idx >= 0, "backendFileDescriptor", SD_JSON_BUILD_INTEGER(backend_idx)),
                                SD_JSON_BUILD_PAIR_STRING("backendPath", pty->backend_path),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        else
                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                                SD_JSON_BUILD_PAIR_CONDITION(frontend_idx >= 0, "frontendFileDescriptor", SD_JSON_BUILD_INTEGER(frontend_idx)),
                                SD_JSON_BUILD_PAIR_CONDITION(backend_idx >= 0, "backendFileDescriptor", SD_JSON_BUILD_INTEGER(backend_idx)),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        if (r < 0)
                return r;

        TAKE_PTR(pty);
        TAKE_PTR(monitor);

        return 0;
}

static int validate_pty_master_fd(int fd, int *ret_pin_fd) {
        assert(fd >= 0);
        assert(ret_pin_fd);

        /* Vet a caller-provided pty frontend ('master') fd before we start operating on it. As a privileged
         * service we must not let a client trick us into acting on an fd it couldn't use itself: reject
         * anything with unexpected open flags (in particular O_PATH, which would smuggle in a reference to an
         * fd the client cannot actually read from or write to), insist on O_RDWR, and require that it's an
         * actual TTY. */
        int fl = fd_verify_safe_flags_full(fd, O_NONBLOCK);
        if (fl < 0)
                return fl;
        if ((fl & O_ACCMODE_STRICT) != O_RDWR)
                return -EACCES;
        if (!isatty_safe(fd))
                return -ENOTTY;

        /* Open the backend ('slave') side through the frontend fd. This confirms it really is the frontend
         * side, and gives us an fd we can pin for later hang-up requests. We keep only an O_PATH reference
         * around: a proper open would keep the backend busy and prevent hang-up detection. */
        _cleanup_close_ int peer_fd = pty_open_peer(fd, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (peer_fd < 0)
                return peer_fd;

        int pin_fd = fd_reopen(peer_fd, O_PATH|O_CLOEXEC);
        if (pin_fd < 0)
                return pin_fd;

        *ret_pin_fd = pin_fd;
        return 0;
}

typedef struct EnrollPtyParameters {
        int frontend_fd_idx;
        FrontendType frontend_type;
        char *name;
        char *description;
        char *tag;
        char *backend_path;
        int monitor;
        bool hang_up_on_disconnect;
        sd_json_variant *terminal_settings; /* no reference */
} EnrollPtyParameters;

static void enroll_pty_parameters_done(EnrollPtyParameters *p) {
        assert(p);

        free(p->name);
        free(p->description);
        free(p->tag);
        free(p->backend_path);
}

static int vl_method_enroll_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        _cleanup_(enroll_pty_parameters_done) EnrollPtyParameters p = {
                .frontend_fd_idx = -1,
                .frontend_type = _FRONTEND_TYPE_INVALID,
                .monitor = -1,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "frontendFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,           voffsetof(p, frontend_fd_idx),       SD_JSON_MANDATORY },
                { "frontendType",           _SD_JSON_VARIANT_TYPE_INVALID, dispatch_frontend_type,         voffsetof(p, frontend_type),         SD_JSON_MANDATORY },
                { "backendPath",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, backend_path),          0                 },
                { "name",                   SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, name),                  0                 },
                { "description",            SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, description),           0                 },
                { "tag",                    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string,        voffsetof(p, tag),                   0                 },
                { "monitor",                SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,      voffsetof(p, monitor),               0                 },
                { "hangUpOnDisconnect",     SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, hang_up_on_disconnect), 0                 },
                { "terminalSettings",       SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref, voffsetof(p, terminal_settings),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.enroll-pty",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        /* Taking over a caller-provided fd only makes sense if the broker keeps a copy of the frontend, i.e.
         * for the 'null' and 'log' frontend types. Handing the fd straight back to the caller ('take') would
         * be a no-op since the caller already holds it. */
        if (p.frontend_type == FRONTEND_TAKE)
                return sd_varlink_error_invalid_parameter_name(link, "frontendType");

        if (p.name) {
                if (!pseudo_tty_name_valid(p.name))
                        return sd_varlink_error_invalid_parameter_name(link, "name");

                if (hashmap_get(m->ptys, p.name))
                        return sd_varlink_error(link, "io.systemd.PTYBroker.PtyExists", NULL);
        } else {
                sd_id128_t id;

                r = sd_id128_randomize(&id);
                if (r < 0)
                        return r;

                p.name = strdup(SD_ID128_TO_STRING(id));
                if (!p.name)
                        return log_oom();
        }

        if (p.description && !pseudo_tty_description_valid(p.description))
                return sd_varlink_error_invalid_parameter_name(link, "description");

        if (p.tag && !pseudo_tty_tag_valid(p.tag))
                return sd_varlink_error_invalid_parameter_name(link, "tag");

        if (p.backend_path && (!path_is_absolute(p.backend_path) || !path_is_normalized(p.backend_path)))
                return sd_varlink_error_invalid_parameter_name(link, "backendPath");

        /* Unlike AcquirePty() we do not settle the terminal settings to the broker's defaults: the pty is
         * already set up by the caller, so we leave the existing configuration in place and only merge the
         * IPC-provided settings on top of it. */
        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        if (hashmap_size(m->ptys) >= PSEUDO_TTY_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyPtys", NULL);

        _cleanup_close_ int frontend_fd = sd_varlink_take_fd(link, p.frontend_fd_idx);
        if (frontend_fd < 0)
                return sd_varlink_error_invalid_parameter_name(link, "frontendFileDescriptor");

        _cleanup_close_ int pin_fd = -EBADF;
        r = validate_pty_master_fd(frontend_fd, &pin_fd);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "frontendFileDescriptor");

        _cleanup_(pseudo_tty_freep) PseudoTTY *pty = NULL;
        r = pseudo_tty_new(&pty);
        if (r < 0)
                return r;

        pty->frontend_fd = TAKE_FD(frontend_fd);
        pty->pin_fd = TAKE_FD(pin_fd);

        pty->name = TAKE_PTR(p.name);
        pty->description = TAKE_PTR(p.description);
        pty->tag = TAKE_PTR(p.tag);
        pty->backend_path = TAKE_PTR(p.backend_path);
        pty->frontend_type = p.frontend_type;
        pty->backend_type = BACKEND_TAKE; /* The backend (i.e. 'slave') stays under the caller's control. */
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(ts);

        /* Apply any IPC-provided dimensions to the pty (merging them onto whatever is already in effect) and
         * read back the settled size. */
        (void) terminal_settings_sync_size_fd(&pty->terminal_settings, pty->frontend_fd, pty->backend_path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return r;

        r = pseudo_tty_watch_frontend_fd(pty, m->event);
        if (r < 0)
                return r;

        /* Also watch the backend device node for removal. For FRONTEND_TAKE we handed the frontend fd to the
         * client and no longer hold one to watch for EPOLLHUP, so this is how we learn the PTY is gone. */
        r = pseudo_tty_watch_backend_node(pty, m->event);
        if (r < 0)
                return r;

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = NULL;
        if (p.monitor > 0) {
                assert(pty->frontend_fd >= 0);

                r = pseudo_tty_monitor_new(link, &monitor);
                if (r < 0)
                        return log_oom();

                monitor->hang_up_on_disconnect = p.hang_up_on_disconnect;
        }

        /* Link everything into the manager *before* sending the (upgrade) response — see the matching comment
         * in vl_method_acquire_pty() for the rationale. */
        r = pseudo_tty_link(pty, m);
        if (r < 0)
                return r;

        if (monitor)
                pseudo_tty_monitor_link(monitor, pty);

        if (p.monitor > 0)
                r = sd_varlink_respond_and_upgradebo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        else
                r = sd_varlink_replybo(
                                link,
                                SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                                JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        if (r < 0)
                return r;

        TAKE_PTR(pty);
        TAKE_PTR(monitor);

        return 0;
}

static int vl_method_monitor_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_UPGRADE));

        struct {
                const char *name;
                size_t track_buffer_lines;
                bool hang_up_on_disconnect;
                sd_json_variant *terminal_settings; /* no reference */
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string,  voffsetof(p, name),                  SD_JSON_MANDATORY },
                { "trackBufferLines",   _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,          voffsetof(p, track_buffer_lines),    0                 },
                { "hangUpOnDisconnect", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_stdbool,       voffsetof(p, hang_up_on_disconnect), 0                 },
                { "terminalSettings",   SD_JSON_VARIANT_OBJECT,        sd_json_dispatch_variant_noref, voffsetof(p, terminal_settings),     0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.monitor-pty",
                        (const char**) STRV_MAKE("pty", p.name),
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        PseudoTTY *pty = hashmap_get(m->ptys, p.name);
        if (!pty)
                return sd_varlink_error(link, "io.systemd.PTYBroker.NoSuchPty", NULL);

        if (pty->frontend_fd < 0)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TrackingNotEnabled", NULL);

        if (pty->n_monitors >= MONITOR_MAX)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TooManyMonitors", NULL);

        _cleanup_(terminal_settings_done) TerminalSettings merged_ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_copy(&merged_ts, &pty->terminal_settings);
        if (r < 0)
                return r;

        r = terminal_settings_merge(&merged_ts, &ts);
        if (r < 0)
                return r;

        _cleanup_(pseudo_tty_monitor_freep) PseudoTTYMonitor *monitor = NULL;
        r = pseudo_tty_monitor_new(link, &monitor);
        if (r < 0)
                return log_oom();

        monitor->hang_up_on_disconnect = p.hang_up_on_disconnect;

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tb = NULL;
        r = pseudo_tty_track_buffer_to_json(pty, p.track_buffer_lines, &tb);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire track buffer: %m");

        /* Wire the monitor up before enqueuing the upgrade reply: the upgrade callback (which needs the
         * monitor as connection userdata) may fire as soon as the reply has been flushed. */
        pseudo_tty_monitor_link(monitor, pty);

        /* Move the new dimensions over */
        terminal_settings_done(&pty->terminal_settings);
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(merged_ts);

        /* Apply them to the TTY device */
        (void) terminal_settings_sync_size_fd(&pty->terminal_settings, pty->frontend_fd, pty->backend_path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire terminal settings: %m");

        r = sd_varlink_respond_and_upgradebo(
                        link,
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("trackBuffer", tb),
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
        if (r < 0)
                return r;

        TAKE_PTR(monitor);
        return 0;
}

static int vl_method_configure_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        struct {
                const char *name;
                sd_json_variant *terminal_settings; /* no reference */
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",             SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string,  voffsetof(p, name),              SD_JSON_MANDATORY },
                { "terminalSettings", SD_JSON_VARIANT_OBJECT, sd_json_dispatch_variant_noref, voffsetof(p, terminal_settings), 0                 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        _cleanup_(terminal_settings_done) TerminalSettings ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_from_json(p.terminal_settings, &ts);
        if (r < 0)
                return sd_varlink_error_invalid_parameter_name(link, "terminalSettings");

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.configure-pty",
                        (const char**) STRV_MAKE("pty", p.name),
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        PseudoTTY *pty = hashmap_get(m->ptys, p.name);
        if (!pty)
                return sd_varlink_error(link, "io.systemd.PTYBroker.NoSuchPty", NULL);

        if (pty->frontend_fd < 0)
                return sd_varlink_error(link, "io.systemd.PTYBroker.TrackingNotEnabled", NULL);

        _cleanup_(terminal_settings_done) TerminalSettings merged_ts = TERMINAL_SETTINGS_NULL;
        r = terminal_settings_copy(&merged_ts, &pty->terminal_settings);
        if (r < 0)
                return r;

        r = terminal_settings_merge(&merged_ts, &ts);
        if (r < 0)
                return r;

        terminal_settings_done(&pty->terminal_settings);
        pty->terminal_settings = TAKE_TERMINAL_SETTINGS(merged_ts);

        (void) terminal_settings_sync_size_fd(&pty->terminal_settings, pty->frontend_fd, pty->backend_path);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *tsj = NULL;
        r = terminal_settings_to_json(&pty->terminal_settings, &tsj);
        if (r < 0)
                return log_error_errno(r, "Failed to acquire terminal settings: %m");

        return sd_varlink_replybo(
                        link,
                        JSON_BUILD_PAIR_VARIANT_NON_NULL("terminalSettings", tsj));
}

static int pseudo_tty_reply_description(PseudoTTY *pty, sd_varlink *link) {
        assert(pty);
        assert(link);

        return sd_varlink_replybo(
                        link,
                        SD_JSON_BUILD_PAIR_STRING("name", pty->name),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("description", pty->description),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("tag", pty->tag),
                        JSON_BUILD_PAIR_ENUM("frontendType", frontend_type_to_string(pty->frontend_type)),
                        JSON_BUILD_PAIR_ENUM("backendType", backend_type_to_string(pty->backend_type)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("backendPath", pty->backend_path));
}

static int vl_method_list_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);
        assert(FLAGS_SET(flags, SD_VARLINK_METHOD_MORE));

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, 0},
                {}
        };

        /* ListPty() takes no input parameters. */
        const char *name = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &name);
        if (r != 0)
                return r;

        r = sd_varlink_set_sentinel(link, "io.systemd.PTYBroker.NoSuchPty");
        if (r < 0)
                return r;

        PseudoTTY *pty;
        if (name) {
                pty = hashmap_get(m->ptys, name);
                if (pty) {
                        r = pseudo_tty_reply_description(pty, link);
                        if (r < 0)
                                return r;
                }
        } else {
                HASHMAP_FOREACH(pty, m->ptys) {
                        r = pseudo_tty_reply_description(pty, link);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

static int vl_method_hang_up_pty(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        assert(link);
        assert(parameters);

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, 0, SD_JSON_MANDATORY },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        /* HangUpPty() takes no input parameters. */
        const char *name = NULL;
        r = sd_varlink_dispatch(link, parameters, dispatch_table, &name);
        if (r != 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        /* bus= */ NULL,
                        "io.systemd.PTYBroker.hang-up-pty",
                        /* details= */ NULL,
                        &m->polkit_registry);
        if (r <= 0)
                return r;

        PseudoTTY *pty = hashmap_get(m->ptys, name);
        if (!pty)
                return sd_varlink_error(link, "io.systemd.PTYBroker.NoSuchPty", NULL);

        r = pseudo_tty_vhangup(pty);
        if (r < 0)
                return r;

        r = set_ensure_put(&pty->vhangup_links, &varlink_hash_ops, link);
        if (r < 0)
                return r;

        sd_varlink_ref(link);

        return sd_varlink_reply(link, NULL);
}

#define EXIT_ON_IDLE_USEC (3 * USEC_PER_SEC)

static bool manager_is_idle(Manager *m) {
        assert(m);

        /* "Idle" means that no Varlink client is currently connected *and* no PTYs are allocated anymore. We
         * must check both: PTYs may outlive the connection that created them (e.g. for the 'take' frontend,
         * where we hand the frontend fd to the client and drop the connection), so an absence of connections
         * alone is not sufficient — that's also why we can't just use sd_varlink_server_set_exit_on_idle(). */

        return sd_varlink_server_current_connections(m->varlink_server) == 0 &&
                hashmap_isempty(m->ptys);
}

static int on_exit_on_idle(sd_event_source *s, uint64_t usec, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        /* Re-check before acting: a client might have reconnected (or a PTY been allocated) during the grace
         * period. */
        if (!manager_is_idle(m))
                return 0;

        log_debug("Still idle after grace period, exiting.");
        return sd_event_exit(m->event, 0);
}

static void manager_schedule_idle_check(Manager *m) {
        int r;

        assert(m);

        /* As a socket-activated singleton, exit once fully idle so we get garbage collected. Don't exit right
         * away though, but arm a short grace timer first, so that a client that reconnects quickly (e.g.
         * between two Varlink calls) doesn't pay the cost of us shutting down and being respawned. */

        if (!manager_is_idle(m)) {
                (void) sd_event_source_set_enabled(m->exit_on_idle_event_source, SD_EVENT_OFF);
                return;
        }

        /* force_reset=true: restart the grace period from scratch every time we become idle again. */
        r = event_reset_time_relative(
                        m->event,
                        &m->exit_on_idle_event_source,
                        CLOCK_MONOTONIC,
                        EXIT_ON_IDLE_USEC,
                        /* accuracy= */ 0,
                        on_exit_on_idle,
                        m,
                        SD_EVENT_PRIORITY_NORMAL,
                        "exit-on-idle",
                        /* force_reset= */ true);
        if (r < 0)
                log_warning_errno(r, "Failed to arm exit-on-idle timer, ignoring: %m");
}

static void manager_on_disconnect(sd_varlink_server *server, sd_varlink *link, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(server);
        assert(link);

        manager_schedule_idle_check(m);
}

static int on_ptys_free_queue(sd_event_source *s, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        assert(s);

        PseudoTTY *pty;
        while ((pty = m->ptys_free_queue))
                pseudo_tty_free(pty);

        manager_schedule_idle_check(m);
        return 0;
}

static int manager_new(RuntimeScope scope, Manager **ret) {
        int r;

        assert(ret);
        assert(IN_SET(scope, RUNTIME_SCOPE_SYSTEM, RUNTIME_SCOPE_USER));

        _cleanup_(manager_freep) Manager *m = new(Manager, 1);
        if (!m)
                return -ENOMEM;

        *m = (Manager) {
                .scope = scope,
        };

        r = sd_event_new(&m->event);
        if (r < 0)
                return r;

        r = sd_event_set_signal_exit(m->event, true);
        if (r < 0)
                return r;

        r = sd_event_add_signal(m->event, /* ret= */ NULL, (SIGRTMIN+18)|SD_EVENT_SIGNAL_PROCMASK, sigrtmin18_handler, /* userdata= */ NULL);
        if (r < 0)
                return r;

        r = sd_event_add_memory_pressure(m->event, /* ret= */ NULL, /* callback= */ NULL, /* userdata= */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to allocate memory pressure event source, ignoring: %m");

        r = sd_event_add_defer(m->event, &m->ptys_free_queue_event_source, on_ptys_free_queue, m);
        if (r < 0)
                return r;

        r = sd_event_source_set_enabled(m->ptys_free_queue_event_source, SD_EVENT_OFF);
        if (r < 0)
                return r;

        (void) sd_event_source_set_description(m->ptys_free_queue_event_source, "ptys-free-queue");

        (void) sd_event_set_watchdog(m->event, true);

        *ret = TAKE_PTR(m);
        return 0;
}

static int manager_startup(Manager *m) {
        int r;

        assert(m);

        r = varlink_server_new(
                        &m->varlink_server,
                        (m->scope != RUNTIME_SCOPE_USER ? SD_VARLINK_SERVER_ACCOUNT_UID : 0)|
                        SD_VARLINK_SERVER_INHERIT_USERDATA|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_INPUT|
                        SD_VARLINK_SERVER_ALLOW_FD_PASSING_OUTPUT,
                        m);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate Varlink server: %m");

        r = sd_varlink_server_add_interface_many(
                        m->varlink_server,
                        &vl_interface_io_systemd_PTYBroker,
                        &vl_interface_io_systemd_service);
        if (r < 0)
                return log_error_errno(r, "Failed to add interfaces to Varlink server: %m");

        r = sd_varlink_server_bind_method_many(
                        m->varlink_server,
                        "io.systemd.PTYBroker.AcquirePty",   vl_method_acquire_pty,
                        "io.systemd.PTYBroker.EnrollPty",    vl_method_enroll_pty,
                        "io.systemd.PTYBroker.MonitorPty",   vl_method_monitor_pty,
                        "io.systemd.PTYBroker.ConfigurePty", vl_method_configure_pty,
                        "io.systemd.PTYBroker.ListPty",      vl_method_list_pty,
                        "io.systemd.PTYBroker.HangUpPty",    vl_method_hang_up_pty);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink methods: %m");

        r = varlink_set_info_systemd(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to set Varlink server info: %m");

        r = sd_varlink_server_listen_auto(m->varlink_server);
        if (r < 0)
                return log_error_errno(r, "Failed to bind to passed Varlink sockets: %m");
        if (r == 0) {
                /* Not socket activated, bind our own socket as a fallback. */
                _cleanup_free_ char *socket_path = NULL;
                r = runtime_directory_generic(m->scope, "systemd/io.systemd.PTYBroker", &socket_path);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine Varlink socket path: %m");

                r = sd_varlink_server_listen_address(m->varlink_server, socket_path, runtime_scope_to_socket_mode(m->scope) | SD_VARLINK_SERVER_MODE_MKDIR_0755);
                if (r < 0)
                        return log_error_errno(r, "Failed to bind to io.systemd.PTYBroker Varlink socket: %m");
        }

        r = sd_varlink_server_bind_disconnect(m->varlink_server, manager_on_disconnect);
        if (r < 0)
                return log_error_errno(r, "Failed to bind Varlink disconnect handler: %m");

        r = sd_varlink_server_attach_event(m->varlink_server, m->event, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach Varlink server to event loop: %m");

        /* Arm the idle timer right away: if we were started but nobody ever connects (e.g. a spurious socket
         * activation), we'll shut down again after the grace period instead of lingering forever. */
        manager_schedule_idle_check(m);

        return 0;
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        RuntimeScope scope = RUNTIME_SCOPE_SYSTEM;
        r = service_parse_argv(
                        "systemd-ptybrokerd.service",
                        "Broker access to pseudo terminals",
                        /* bus_objects= */ NULL,
                        &scope,
                        argc, argv);
        if (r <= 0)
                return r;

        umask(0022);

        _cleanup_(manager_freep) Manager *m = NULL;
        r = manager_new(scope, &m);
        if (r < 0)
                return log_error_errno(r, "Failed to create manager: %m");

        r = manager_startup(m);
        if (r < 0)
                return r;

        _unused_ _cleanup_(notify_on_cleanup) const char *notify_stop =
                notify_start(NOTIFY_READY_MESSAGE, NOTIFY_STOPPING_MESSAGE);

        r = sd_event_loop(m->event);
        if (r < 0)
                return log_error_errno(r, "Event loop failed: %m");

        return 0;
}

DEFINE_MAIN_FUNCTION(run);
