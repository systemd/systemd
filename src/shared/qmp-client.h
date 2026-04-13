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

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd. Performs the
 * QMP handshake (greeting + qmp_capabilities) using a process+wait loop. Call
 * qmp_client_attach_event() afterwards for async operation via sd_event. */
int qmp_client_connect_fd(QmpClient **ret, int fd);

int qmp_client_attach_event(QmpClient *c, sd_event *event, int64_t priority);

/* Send a QMP command asynchronously. The callback is invoked exactly once from the sd-event loop when
 * the matching response arrives or the connection drops (-ECONNRESET). Returns 0 if the command was
 * sent and registered (callback will be invoked later), negative errno on failure (callback NOT invoked). */
int qmp_client_invoke(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata);

int qmp_client_push_fd(QmpClient *c, int fd);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback);
void *qmp_client_set_userdata(QmpClient *c, void *userdata);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event *qmp_client_get_event(QmpClient *c);
unsigned qmp_client_next_fdset_id(QmpClient *client);

/* Send a synchronous QMP command and wait for the response (process+wait loop).
 * Matches sd_varlink_call(). Returns borrowed references into the pinned response
 * (valid until next call/close). Returns 1 on success (reply received), -EIO on
 * QMP error when ret_error_desc is NULL, negative errno on transport failure. */
int qmp_client_call(
                QmpClient *c,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                const char **ret_error_desc);

QmpClient* qmp_client_unref(QmpClient *p);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);
