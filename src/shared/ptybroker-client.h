/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"
#include "sd-varlink.h"

#include "runtime-scope.h"

int pty_broker_connect(RuntimeScope scope, sd_varlink **ret);
int pty_broker_terminal_settings_to_json(sd_json_variant **ret);

/* Acquires a pseudo TTY from ptybrokerd. The broker takes over the frontend (the "master" side), either
 * discarding its output (frontend_type "null") or writing it to the logs (frontend_type "log"), while
 * handing us both a monitor connection (a protocol-upgraded, bidirectional socket that carries the frontend's
 * output to us and forwards our input back to it — to be used as PTY forwarder "master") and the backend (the
 * "slave" side), so that we can run a payload on it. Returns the monitor fd in *ret_monitor_fd, the backend fd
 * in *ret_backend_fd, and, if non-NULL, the name the broker registered the PTY under in *ret_name. */
int pty_broker_acquire_pty(
                RuntimeScope scope,
                const char *frontend_type,
                const char *name,
                int *ret_monitor_fd,
                int *ret_backend_fd,
                char **ret_name);

/* Enrolls a caller-allocated pseudo TTY frontend (the "master" side) with ptybrokerd. Unlike
 * pty_broker_acquire_pty() above, the broker does not allocate the pty; the caller passes in the frontend fd
 * it already holds (e.g. one allocated inside a namespace) and retains ownership of it. The broker takes over
 * the frontend's output (frontend_type "null" discards it, "log" also writes it to the logs) and hands back a
 * monitor connection (a protocol-upgraded, bidirectional socket carrying the frontend's output to us and our
 * input back to it — to be used as PTY forwarder "master"). Returns the monitor fd in *ret_monitor_fd, and,
 * if non-NULL, the name the broker registered the PTY under in *ret_name. */
int pty_broker_enroll_pty(
                RuntimeScope scope,
                int frontend_fd,
                const char *frontend_type,
                const char *name,
                int *ret_monitor_fd,
                char **ret_name);
