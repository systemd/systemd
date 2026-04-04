/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-json.h"

#include "cleanup-util.h"

typedef struct QmpClient QmpClient;

typedef void (*qmp_event_callback_t)(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                void *userdata);

typedef void (*qmp_disconnect_callback_t)(
                QmpClient *client,
                void *userdata);

/* Callback for async command completion. On success: result is non-NULL, error_class is NULL, error is 0.
 * On QMP error: result is NULL, error_class is the QMP error class string, error is -EIO.
 * On transport failure: result and error_class are NULL, error is a negative errno. */
typedef void (*qmp_command_callback_t)(
                QmpClient *client,
                sd_json_variant *result,
                const char *error_class,
                int error,
                void *userdata);

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd (closes it on error or when
 * the QmpClient is freed). Performs a blocking handshake: reads greeting, sends qmp_capabilities, waits
 * for success. The fd remains in blocking mode for subsequent qmp_client_call() invocations; call
 * qmp_client_start_async() to switch to non-blocking event-driven operation. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event);

/* Switch from blocking setup phase to async event processing. Must be called
 * after all blocking setup (qmp_client_call, drive config, cont). */
int qmp_client_start_async(QmpClient *client);

/* Execute a QMP command synchronously (blocking). Only valid before qmp_client_start_async().
 * Returns 0 on success (result in ret_result), -EIO on QMP error (class in ret_error),
 * negative errno on transport failure. ret_result and ret_error may be NULL. */
int qmp_client_call(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                char **ret_error);

/* Like qmp_client_call(), but sends an FD as SCM_RIGHTS ancillary data alongside
 * the command message. Used for the QEMU "getfd" command. */
int qmp_client_call_send_fd(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                int fd,
                sd_json_variant **ret_result,
                char **ret_error);

/* Send a QMP command asynchronously. The callback is invoked exactly once from the sd-event loop when
 * the matching response arrives or the connection drops (-ECONNRESET). Returns 0 if the command was
 * sent and registered (callback will be invoked later), negative errno on failure (callback NOT invoked). */
int qmp_client_execute(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                qmp_command_callback_t callback,
                void *userdata);
void qmp_client_set_event_callback(QmpClient *client, qmp_event_callback_t callback, void *userdata);
void qmp_client_set_disconnect_callback(QmpClient *client, qmp_disconnect_callback_t callback, void *userdata);
sd_event *qmp_client_get_event(QmpClient *client);
QmpClient *qmp_client_free(QmpClient *client);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_free);
