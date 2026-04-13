/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"

typedef struct QmpClient QmpClient;

typedef int (*qmp_event_callback_t)(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata);

typedef void (*qmp_disconnect_callback_t)(
                QmpClient *client,
                void *userdata);

/* Callback for async command completion. On success: result is non-NULL, error_desc is NULL, error is 0.
 * On QMP error: result is NULL, error_desc is the human-readable QMP error description, error is -EIO.
 * On transport failure: result and error_desc are NULL, error is a negative errno.
 *
 * Return value: 0 to continue, or the return value of sd_event_exit() to request event loop shutdown. */
typedef int (*qmp_command_callback_t)(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_desc,
                int error,
                void *userdata);

/* Bundles command parameters and any SCM_RIGHTS fds for a single QMP command. Passed to
 * qmp_client_invoke() and qmp_client_call() so that fds and arguments arrive together
 * (no separate push_fd step that would race against internal handshake/probe enqueues).
 *
 * Fd ownership: the fds in .fds are owned-by-callee. On success the call has transferred
 * them onto the underlying stream and they will be closed when consumed by sendmsg or when
 * the stream is destroyed. On failure the call has closed any fds it had already accepted
 * before the failure. In both cases the caller's int variables become invalid; use
 * TAKE_FD() at the call site to mark the transfer. (Matches sd_varlink_push_fd() ownership
 * semantics.)
 *
 * The struct is mutated by invoke/call: .fds and .n_fds are advanced as fds are staged,
 * and .n_fds is set to 0 once ownership has fully moved to the stream. Construct a fresh
 * QmpClientArgs per call (the QMP_CLIENT_ARGS* macros do this); never reuse one. */
typedef struct QmpClientArgs {
        sd_json_variant *arguments;   /* command parameters; may be NULL */
        const int *fds;               /* fds to pass via SCM_RIGHTS; may be NULL */
        size_t n_fds;
} QmpClientArgs;

/* Convenience constructors for the common shapes. Use as a function-call argument: the
 * compound literal lives until the end of the full expression containing the call. */
#define QMP_CLIENT_ARGS(args_) \
        (&(QmpClientArgs){ .arguments = (args_) })
#define QMP_CLIENT_ARGS_FD(args_, fd_) \
        (&(QmpClientArgs){ .arguments = (args_), .fds = (int[]){ (fd_) }, .n_fds = 1 })

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd. Performs the
 * QMP handshake (greeting + qmp_capabilities) using a process+wait loop. Call
 * qmp_client_attach_event() afterwards for async operation via sd_event. */
int qmp_client_connect_fd(QmpClient **ret, int fd);

int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority);

/* Send a QMP command asynchronously. The callback is invoked exactly once from the sd-event
 * loop when the matching response arrives or the connection drops (-ECONNRESET). Pass NULL
 * for args when the command takes no arguments and no fds; otherwise use QMP_CLIENT_ARGS()
 * or QMP_CLIENT_ARGS_FD(). Returns 0 if the command was sent and registered (callback will
 * be invoked later), negative errno on failure (callback NOT invoked). See QmpClientArgs
 * for the fd-ownership contract. */
int qmp_client_invoke(
                QmpClient *client,
                const char *command,
                QmpClientArgs *args,
                qmp_command_callback_t callback,
                void *userdata);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback);
void *qmp_client_set_userdata(QmpClient *c, void *userdata);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event *qmp_client_get_event(QmpClient *c);
unsigned qmp_client_next_fdset_id(QmpClient *client);

/* Send a synchronous QMP command and wait for the response (process+wait loop).
 * Matches sd_varlink_call(). Pass NULL for args when the command takes no arguments and no
 * fds. Returns borrowed references into the pinned response (valid until next call/close).
 * Returns 1 on success (reply received), -EIO on QMP error when ret_error_desc is NULL,
 * negative errno on transport failure. See QmpClientArgs for the fd-ownership contract. */
int qmp_client_call(
                QmpClient *c,
                const char *command,
                QmpClientArgs *args,
                sd_json_variant **ret_result,
                const char **ret_error_desc);

QmpClient* qmp_client_unref(QmpClient *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);
