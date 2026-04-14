/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "hashmap.h"
#include "log.h"
#include "ovsdb-rpc.h"

typedef struct OVSDBRpcRequest {
        uint64_t id;
        ovsdb_reply_cb_t cb;
        void *userdata;
} OVSDBRpcRequest;

void ovsdb_rpc_layer_init(OVSDBRpcLayer *rpc) {
        assert(rpc);

        *rpc = (OVSDBRpcLayer) {
                .next_id = 1,
        };
}

void ovsdb_rpc_layer_done(OVSDBRpcLayer *rpc) {
        assert(rpc);

        hashmap_free(rpc->in_flight);
}

int ovsdb_rpc_build_request(
                OVSDBRpcLayer *rpc,
                const char *method,
                sd_json_variant *params,
                ovsdb_reply_cb_t cb,
                void *userdata,
                sd_json_variant **ret_message,
                uint64_t *ret_id) {

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *message = NULL;
        _cleanup_free_ OVSDBRpcRequest *req = NULL;
        uint64_t id;
        int r;

        assert(rpc);
        assert(method);
        assert(ret_message);

        /* Guard against next_id wrapping to 0 — 0 maps to NULL hashmap key */
        if (rpc->next_id == 0)
                rpc->next_id = 1;

        id = rpc->next_id++;

        req = new(OVSDBRpcRequest, 1);
        if (!req)
                return log_debug_errno(SYNTHETIC_ERRNO(ENOMEM), "OVSDB RPC: failed to allocate request");

        *req = (OVSDBRpcRequest) {
                .id = id,
                .cb = cb,
                .userdata = userdata,
        };

        /* Key by &req->id (a pointer into the value) using uint64 hash ops, so the lookup is
         * correct on 32bit too, where casting a uint64_t id to a pointer would truncate it. */
        r = hashmap_ensure_put(&rpc->in_flight, &uint64_hash_ops_value_free, &req->id, req);
        if (r < 0)
                return log_debug_errno(r, "OVSDB RPC: failed to register in-flight request: %m");

        TAKE_PTR(req);

        r = sd_json_buildo(
                        &message,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        SD_JSON_BUILD_PAIR("params", SD_JSON_BUILD_VARIANT(params)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", id));
        if (r < 0) {
                free(hashmap_remove(rpc->in_flight, &id));
                return log_debug_errno(r, "OVSDB RPC: failed to build request message: %m");
        }

        *ret_message = TAKE_PTR(message);
        if (ret_id)
                *ret_id = id;
        return 0;
}

void ovsdb_rpc_cancel_request(OVSDBRpcLayer *rpc, uint64_t id) {
        assert(rpc);

        /* Synchronous rollback path: the caller failed to enqueue a request it just
         * registered, and reports the failure through its own return value. Unlike
         * ovsdb_rpc_layer_cancel_all() (the asynchronous teardown path), we deliberately
         * do NOT invoke the callback here — it would double-report the same error. */
        free(hashmap_remove(rpc->in_flight, &id));
}

typedef struct OVSDBMessage {
        sd_json_variant *id;
        sd_json_variant *method;
        sd_json_variant *params;
        sd_json_variant *result;
        sd_json_variant *error;
} OVSDBMessage;

int ovsdb_rpc_layer_dispatch(
                OVSDBRpcLayer *rpc,
                OVSDBClient *client,
                sd_json_variant *message,
                ovsdb_notify_cb_t notify_cb,
                void *notify_userdata) {

        OVSDBMessage m = {};
        int r;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "id",     _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(m, id),     0 },
                { "method", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(m, method), 0 },
                { "params", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(m, params), 0 },
                { "result", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(m, result), 0 },
                { "error",  _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_variant_noref, voffsetof(m, error),  0 },
                {}
        };

        assert(rpc);
        assert(message);

        r = sd_json_dispatch(message, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &m);
        if (r < 0)
                return log_debug_errno(r, "OVSDB RPC: failed to parse incoming message: %m");

        /* Server-originated notification: has a string "method" key and null (or absent) id.
         * Echo requests (method + non-null id) are handled in ovsdb-client.c dispatch
         * loop before reaching here. A non-string/null "method" is not a notification;
         * fall through so a message carrying an unsigned id is still routed as a reply. */
        if (m.method && sd_json_variant_is_string(m.method) &&
            (!m.id || sd_json_variant_is_null(m.id))) {
                const char *method = sd_json_variant_string(m.method);

                log_debug("OVSDB RPC: received notification method='%s'", method);

                if (notify_cb)
                        return notify_cb(client, method, m.params, notify_userdata);

                return 0;
        }

        /* Reply: has unsigned id */
        if (m.id && sd_json_variant_is_unsigned(m.id)) {
                _cleanup_free_ OVSDBRpcRequest *req = NULL;
                sd_json_variant *result, *error;
                uint64_t id;

                id = sd_json_variant_unsigned(m.id);

                req = hashmap_remove(rpc->in_flight, &id);
                if (!req)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "OVSDB RPC: received reply for unknown id=%" PRIu64, id);

                /* Normalize JSON null to C NULL */
                result = m.result && !sd_json_variant_is_null(m.result) ? m.result : NULL;
                error = m.error && !sd_json_variant_is_null(m.error) ? m.error : NULL;

                log_debug("OVSDB RPC: dispatching reply for id=%" PRIu64, id);

                if (req->cb)
                        return req->cb(client, result, error, req->userdata);

                return 0;
        }

        return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "OVSDB RPC: structurally invalid message");
}

void ovsdb_rpc_layer_cancel_all(
                OVSDBRpcLayer *rpc,
                OVSDBClient *client,
                sd_json_variant *synthetic_error) {

        OVSDBRpcRequest *req;

        assert(rpc);

        while ((req = hashmap_steal_first(rpc->in_flight))) {
                if (req->cb)
                        (void) req->cb(client, /* result= */ NULL, synthetic_error, req->userdata);

                free(req);
        }
}
