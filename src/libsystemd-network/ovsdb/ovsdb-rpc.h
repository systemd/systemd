/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "ovsdb-forward.h"

typedef struct OVSDBRpc {
        Hashmap *in_flight;   /* uint64_t id → OVSDBRpcRequest* */
        uint64_t next_id;
} OVSDBRpc;

void ovsdb_rpc_init(OVSDBRpc *rpc);
void ovsdb_rpc_done(OVSDBRpc *rpc);

/* Build a request message, register callback in in_flight table */
int ovsdb_rpc_build_request(
                OVSDBRpc *rpc,
                const char *method,
                sd_json_variant *params,
                ovsdb_reply_callback_t cb,
                void *userdata,
                sd_json_variant **ret_message,
                uint64_t *ret_id);

/* Cancel a single in-flight request by id */
void ovsdb_rpc_cancel_request(OVSDBRpc *rpc, uint64_t id);

/* Dispatch an incoming message: route to callback or notification handler */
int ovsdb_rpc_dispatch(
                OVSDBRpc *rpc,
                OVSDBClient *client,
                sd_json_variant *message,
                ovsdb_notify_callback_t notify_cb,
                void *notify_userdata);

/* Cancel all in-flight requests with a synthetic error */
void ovsdb_rpc_cancel_all(
                OVSDBRpc *rpc,
                OVSDBClient *client,
                sd_json_variant *synthetic_error);
