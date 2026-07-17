/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "log.h"
#include "path-lookup.h"
#include "ptybroker-client.h"
#include "string-util.h"
#include "terminal-util.h"

int pty_broker_connect(RuntimeScope scope, sd_varlink **ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(scope, "systemd/io.systemd.PTYBroker", &socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to determine ptybrokerd socket path: %m");

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = sd_varlink_connect_address(&vl, socket_path);
        if (r < 0)
                return log_error_errno(r, "Failed to connect to ptybrokerd: %m");

        *ret = TAKE_PTR(vl);
        return 0;
}

int pty_broker_terminal_settings_to_json(sd_json_variant **ret) {
        assert(ret);

        /* Assembles a TerminalSettings object describing the caller's terminal environment and dimensions, so
         * that the broker can make the allocated PTY match the local terminal as closely as possible. Values
         * that are unset or unavailable are simply omitted, in which case the broker applies its own
         * defaults. $NO_COLOR follows the no-color.org semantics: any non-empty value disables color, which
         * the broker expresses as a boolean. */

        const char *term = empty_to_null(getenv("TERM"));
        const char *colorterm = empty_to_null(getenv("COLORTERM"));
        bool no_color = !isempty(getenv("NO_COLOR"));

        int columns = fd_columns(STDIN_FILENO);
        int lines = fd_lines(STDIN_FILENO);

        return sd_json_buildo(
                        ret,
                        SD_JSON_BUILD_PAIR_CONDITION(!!term, "dollarTERM", SD_JSON_BUILD_STRING(term)),
                        SD_JSON_BUILD_PAIR_CONDITION(!!colorterm, "dollarCOLORTERM", SD_JSON_BUILD_STRING(colorterm)),
                        SD_JSON_BUILD_PAIR_CONDITION(no_color, "dollarNO_COLOR", SD_JSON_BUILD_BOOLEAN(true)),
                        SD_JSON_BUILD_PAIR_CONDITION(columns > 0, "columns", SD_JSON_BUILD_UNSIGNED(columns)),
                        SD_JSON_BUILD_PAIR_CONDITION(lines > 0, "lines", SD_JSON_BUILD_UNSIGNED(lines)));
}

int pty_broker_acquire_pty(
                RuntimeScope scope,
                const char *frontend_type,
                const char *name,
                int *ret_monitor_fd,
                int *ret_backend_fd,
                char **ret_name) {

        int r;

        assert(frontend_type);
        assert(ret_monitor_fd);
        assert(ret_backend_fd);

        /* Acquire a pseudo TTY from ptybrokerd. We ask the broker to take over the frontend (i.e. the
         * "master" side) itself — either discarding its output ("null") or writing it to the logs ("log") —
         * while acquiring a monitor connection on the same frontend. The monitor connection is a
         * protocol-upgraded, bidirectional socket that carries the frontend's output to us and forwards our
         * input back to it: it's meant to be used as PTY forwarder "master". The backend (i.e. the "slave"
         * side) is handed to us as-is, so that we can invoke a payload on it. */

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = pty_broker_connect(scope, &vl);
        if (r < 0)
                return r;

        r = sd_varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable file descriptor passing on ptybrokerd connection: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ts = NULL;
        r = pty_broker_terminal_settings_to_json(&ts);
        if (r < 0)
                return log_error_errno(r, "Failed to build terminal settings: %m");

        _cleanup_close_ int input_fd = -EBADF, output_fd = -EBADF;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_call_and_upgradebo(
                        vl,
                        "io.systemd.PTYBroker.AcquirePty",
                        &reply,
                        &error_id,
                        &input_fd,
                        &output_fd,
                        SD_JSON_BUILD_PAIR_STRING("frontendType", frontend_type),
                        SD_JSON_BUILD_PAIR_STRING("backendType", "take"),
                        SD_JSON_BUILD_PAIR_BOOLEAN("monitor", true),
                        SD_JSON_BUILD_PAIR_CONDITION(!!name, "name", SD_JSON_BUILD_STRING(name)),
                        SD_JSON_BUILD_PAIR_VARIANT("terminalSettings", ts));
        if (r < 0)
                return log_error_errno(r, "Failed to call AcquirePty(): %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Failed to acquire PTY from ptybrokerd: %s", error_id);

        struct {
                unsigned backend_fd_idx;
                const char *name;
        } p = {
                .backend_fd_idx = UINT_MAX,
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "backendFileDescriptor", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint,         voffsetof(p, backend_fd_idx), SD_JSON_MANDATORY },
                { "name",                  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, voffsetof(p, name),           0                 },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to parse AcquirePty() reply: %m");

        _cleanup_free_ char *assigned_name = NULL;
        if (ret_name) {
                assigned_name = strdup(strempty(p.name));
                if (!assigned_name)
                        return log_oom();
        }

        _cleanup_close_ int backend_fd = sd_varlink_take_fd(vl, p.backend_fd_idx);
        if (backend_fd < 0)
                return log_error_errno(backend_fd, "Failed to take PTY backend file descriptor from ptybrokerd: %m");

        r = same_fd(input_fd, output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if input/output file descriptors match: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Input/output file descriptor of monitor connection do not match.");

        /* The upgraded monitor connection is a single bidirectional socket, handed to us as two dup'ed fds.
         * The PTY forwarder reads and writes a single "master" fd, so we keep the input side for that and
         * drop the redundant output side. */
        *ret_monitor_fd = TAKE_FD(input_fd);
        *ret_backend_fd = TAKE_FD(backend_fd);
        if (ret_name)
                *ret_name = TAKE_PTR(assigned_name);

        return 0;
}

int pty_broker_enroll_pty(
                RuntimeScope scope,
                int frontend_fd,
                const char *frontend_type,
                const char *name,
                int *ret_monitor_fd,
                char **ret_name) {

        int r;

        assert(frontend_fd >= 0);
        assert(frontend_type);
        assert(ret_monitor_fd);

        /* Enrolls a caller-allocated pseudo TTY frontend (the "master" side) with ptybrokerd. Unlike
         * AcquirePty() the broker does not allocate the pty: we hand it the frontend fd we already have and
         * it takes over the frontend's output — discarding it (frontend_type "null") or additionally writing
         * it to the logs (frontend_type "log") — while handing us a monitor connection (a protocol-upgraded,
         * bidirectional socket that carries the frontend's output to us and forwards our input back to it, to
         * be used as PTY forwarder "master"). The backend (the "slave" side) stays under our control. We
         * deliberately do not pass a backendPath: the caller may have allocated the pty inside a namespace
         * where the path would be meaningless to the broker. */

        _cleanup_(sd_varlink_unrefp) sd_varlink *vl = NULL;
        r = pty_broker_connect(scope, &vl);
        if (r < 0)
                return r;

        r = sd_varlink_set_allow_fd_passing_input(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable file descriptor passing input on ptybrokerd connection: %m");

        r = sd_varlink_set_allow_fd_passing_output(vl, true);
        if (r < 0)
                return log_error_errno(r, "Failed to enable file descriptor passing output on ptybrokerd connection: %m");

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *ts = NULL;
        r = pty_broker_terminal_settings_to_json(&ts);
        if (r < 0)
                return log_error_errno(r, "Failed to build terminal settings: %m");

        /* Duplicate the frontend fd into the message rather than taking possession of it: the caller retains
         * ownership and closes its copy once we return. The broker's copy shares the same open file
         * description, so the frontend stays alive on the broker side. */
        int fd_idx = sd_varlink_push_dup_fd(vl, frontend_fd);
        if (fd_idx < 0)
                return log_error_errno(fd_idx, "Failed to push PTY frontend fd to ptybrokerd: %m");

        _cleanup_close_ int input_fd = -EBADF, output_fd = -EBADF;
        sd_json_variant *reply = NULL;
        const char *error_id = NULL;
        r = sd_varlink_call_and_upgradebo(
                        vl,
                        "io.systemd.PTYBroker.EnrollPty",
                        &reply,
                        &error_id,
                        &input_fd,
                        &output_fd,
                        SD_JSON_BUILD_PAIR_INTEGER("frontendFileDescriptor", fd_idx),
                        SD_JSON_BUILD_PAIR_STRING("frontendType", frontend_type),
                        SD_JSON_BUILD_PAIR_BOOLEAN("monitor", true),
                        SD_JSON_BUILD_PAIR_CONDITION(!!name, "name", SD_JSON_BUILD_STRING(name)),
                        SD_JSON_BUILD_PAIR_VARIANT("terminalSettings", ts));
        if (r < 0)
                return log_error_errno(r, "Failed to call EnrollPty(): %m");
        if (error_id)
                return log_error_errno(sd_varlink_error_to_errno(error_id, reply),
                                       "Failed to enroll PTY with ptybrokerd: %s", error_id);

        struct {
                const char *name;
        } p = {};

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name", SD_JSON_VARIANT_STRING, sd_json_dispatch_const_string, voffsetof(p, name), SD_JSON_MANDATORY },
                {}
        };

        r = sd_json_dispatch(reply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &p);
        if (r < 0)
                return log_error_errno(r, "Failed to parse EnrollPty() reply: %m");

        _cleanup_free_ char *assigned_name = NULL;
        if (ret_name) {
                assigned_name = strdup(p.name);
                if (!assigned_name)
                        return log_oom();
        }

        r = same_fd(input_fd, output_fd);
        if (r < 0)
                return log_error_errno(r, "Failed to check if input/output file descriptors match: %m");
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EPROTO), "Input/output file descriptor of monitor connection do not match.");

        /* As with AcquirePty(), the upgraded monitor connection is a single bidirectional socket handed to us
         * as two dup'ed fds; keep the input side as the forwarder "master" and drop the redundant output. */
        *ret_monitor_fd = TAKE_FD(input_fd);
        if (ret_name)
                *ret_name = TAKE_PTR(assigned_name);

        return 0;
}
