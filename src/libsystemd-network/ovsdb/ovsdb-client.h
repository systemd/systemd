/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-event.h"

#include "ovsdb-forward.h"

typedef enum OVSDBClientState {
        OVSDB_CLIENT_DISCONNECTED,
        OVSDB_CLIENT_HANDSHAKING,
        OVSDB_CLIENT_READY,
        OVSDB_CLIENT_FAILED,
        _OVSDB_CLIENT_STATE_MAX,
        _OVSDB_CLIENT_STATE_INVALID = -EINVAL,
} OVSDBClientState;

typedef int (*ovsdb_state_cb_t)(OVSDBClient *client, OVSDBClientState old_state, OVSDBClientState new_state, void *userdata);

/* Create from pre-connected fd (for tests) */
int ovsdb_client_new_from_fd(OVSDBClient **ret, sd_event *event, int fd);

/* Create with socket path (for production) */
int ovsdb_client_new(OVSDBClient **ret, sd_event *event, const char *socket_path);

OVSDBClient* ovsdb_client_ref(OVSDBClient *c);
OVSDBClient* ovsdb_client_unref(OVSDBClient *c);
DEFINE_TRIVIAL_CLEANUP_FUNC(OVSDBClient*, ovsdb_client_unref);

int ovsdb_client_set_state_cb(OVSDBClient *c, ovsdb_state_cb_t cb, void *userdata);
int ovsdb_client_set_notify_cb(OVSDBClient *c, ovsdb_notify_cb_t cb, void *userdata);
int ovsdb_client_set_update_cb(OVSDBClient *c, ovsdb_update_cb_t cb, void *userdata);

OVSDBClientState ovsdb_client_get_state(const OVSDBClient *c);
OVSDBMonitor* ovsdb_client_get_monitor(const OVSDBClient *c);
sd_json_variant* ovsdb_client_get_schema(const OVSDBClient *c);

/* Start the handshake (sends get_schema). For fd-pair clients, immediately handshakes. */
int ovsdb_client_start(OVSDBClient *c);

/* Issue a JSON-RPC call */
int ovsdb_client_call(OVSDBClient *c, const char *method, sd_json_variant *params, ovsdb_reply_cb_t cb, void *userdata);

/* Subscribe to monitor_cond for OVS tables (Open_vSwitch, Bridge, Port, Interface).
 * Populates the internal OVSDBMonitor cache. The initial_cb is invoked when the
 * initial snapshot arrives (or on error). */
int ovsdb_client_monitor_cond(
                OVSDBClient *c,
                ovsdb_reply_cb_t initial_cb,
                void *userdata);

/* Send a transact request. ops is an array of operation objects (built via
 * ovsdb_op_* helpers). The database name "Open_vSwitch" is prepended automatically. */
int ovsdb_client_transact(
                OVSDBClient *c,
                sd_json_variant *ops,
                ovsdb_reply_cb_t cb,
                void *userdata);
