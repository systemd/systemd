/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"
#include "sd-json.h"

#include "macro.h"

typedef struct QmpClient QmpClient;

typedef void (*qmp_event_callback_t)(
                QmpClient *client,
                const char *event,
                sd_json_variant *data,
                uint64_t timestamp_seconds,
                uint64_t timestamp_microseconds,
                void *userdata);

typedef void (*qmp_disconnect_callback_t)(
                QmpClient *client,
                void *userdata);

/* Connect to QMP via a pre-created socketpair fd. Takes ownership of fd (closes it on error or when
 * the QmpClient is freed). Performs a blocking handshake: reads greeting, sends qmp_capabilities, waits
 * for success. Then switches fd to non-blocking and attaches to sd_event for async event processing. */
int qmp_client_connect_fd(QmpClient **ret, int fd, sd_event *event);
int qmp_client_execute(
                QmpClient *client,
                const char *command,
                sd_json_variant *arguments,
                sd_json_variant **ret_result,
                char **ret_error);
int qmp_client_get_schema(QmpClient *client, sd_json_variant **ret_schema);
void qmp_client_set_event_callback(QmpClient *client, qmp_event_callback_t callback, void *userdata);
void qmp_client_set_disconnect_callback(QmpClient *client, qmp_disconnect_callback_t callback, void *userdata);
QmpClient *qmp_client_free(QmpClient *client);

DEFINE_TRIVIAL_CLEANUP_FUNC(QmpClient *, qmp_client_free);
