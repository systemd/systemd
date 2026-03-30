/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-json.h"

#include "cleanup-util.h"
#include "time-util.h"

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
 * for success. Then switches fd to non-blocking and attaches to sd_event for async event processing. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event);

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
QmpClient *qmp_client_free(QmpClient *client);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_free);
