/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

/* Forward declarations for the OVSDB JSON-RPC client. */

typedef struct OVSDBClient OVSDBClient;
typedef struct OVSDBMonitor OVSDBMonitor;

/* Reply callback. Two normal cases: exactly one of result/error is non-NULL.
 * Third case (teardown): both NULL when the client is being unrefed and
 * ovsdb_rpc_layer_cancel_all() drains in-flight callbacks with a synthetic
 * NULL error. Callbacks must tolerate this and not touch client state that
 * may already be torn down. */
typedef int (*ovsdb_reply_cb_t)(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata);

/* Notification callback: server-initiated message (method present, id null) */
typedef int (*ovsdb_notify_cb_t)(
                OVSDBClient *client,
                const char *method,
                sd_json_variant *params,
                void *userdata);

/* Monitor update callback: fired after update2 is applied to the monitor cache */
typedef void (*ovsdb_update_cb_t)(OVSDBClient *client, void *userdata);
