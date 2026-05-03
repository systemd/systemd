/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-json.h"

/* Forward declarations for the OVSDB JSON-RPC client. */

typedef struct OVSDBClient OVSDBClient;
typedef struct OVSDBMonitor OVSDBMonitor;

/* Reply callback: exactly one of result/error is non-NULL */
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
