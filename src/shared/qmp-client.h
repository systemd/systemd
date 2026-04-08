/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "time-util.h"

typedef struct QmpClient QmpClient;

typedef enum QmpClientFeature {
        QMP_CLIENT_FEATURE_IO_URING = 1 << 0,
        /* Add future feature flags here */
} QmpClientFeature;

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

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd. Attaches to sd_event
 * and performs the QMP handshake (greeting + qmp_capabilities) using sd_event_run() as the
 * wait mechanism — one unified I/O path for both handshake and async operation. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event);

/* Perform a single step of QMP processing. Returns 1 if progress was made, 0 if nothing
 * available, negative on error. Matches sd-varlink's sd_varlink_process() pattern. */
int qmp_client_process(QmpClient *c);

/* Send a QMP command asynchronously. The callback is invoked exactly once from the sd-event loop when
 * the matching response arrives or the connection drops (-ECONNRESET). Returns 0 if the command was
 * sent and registered (callback will be invoked later), negative errno on failure (callback NOT invoked). */
int qmp_client_execute(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata);

/* Like qmp_client_execute(), but sends an FD as SCM_RIGHTS ancillary data alongside
 * the command message. Used for QEMU's "add-fd" and "getfd" commands. */
int qmp_client_execute_send_fd(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                int fd,
                qmp_command_callback_t callback,
                void *userdata);

void qmp_client_bind_event(QmpClient *c, qmp_event_callback_t callback);
void qmp_client_bind_disconnect(QmpClient *c, qmp_disconnect_callback_t callback);
void *qmp_client_set_userdata(QmpClient *c, void *userdata);
void *qmp_client_get_userdata(QmpClient *c);
int qmp_client_set_description(QmpClient *c, const char *description);
sd_event *qmp_client_get_event(QmpClient *c);
bool qmp_client_has_feature(QmpClient *client, QmpClientFeature feature);
unsigned qmp_client_next_fdset_id(QmpClient *client);

int qmp_client_close(QmpClient *c);
QmpClient *qmp_client_close_unref(QmpClient *c);
QmpClient *qmp_client_ref(QmpClient *c);
QmpClient *qmp_client_unref(QmpClient *c);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_unref);
