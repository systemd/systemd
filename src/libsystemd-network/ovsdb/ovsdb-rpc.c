/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "log.h"
#include "macro.h"
#include "ovsdb-rpc.h"

typedef struct OVSDBRpcRequest {
        uint64_t id;
        ovsdb_reply_cb_t cb;
        void *userdata;
} OVSDBRpcRequest;

static void ovsdb_rpc_request_free(OVSDBRpcRequest *req) {
        free(req);
}

DEFINE_PRIVATE_HASH_OPS_WITH_VALUE_DESTRUCTOR(
                ovsdb_rpc_request_hash_ops,
                void,
                trivial_hash_func,
                trivial_compare_func,
                OVSDBRpcRequest,
                ovsdb_rpc_request_free);

void ovsdb_rpc_layer_init(OVSDBRpcLayer *rpc) {
        assert(rpc);

        *rpc = (OVSDBRpcLayer) {
                .next_id = 1,
        };
}

void ovsdb_rpc_layer_done(OVSDBRpcLayer *rpc) {
        if (!rpc)
                return;

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

        r = hashmap_ensure_put(&rpc->in_flight, &ovsdb_rpc_request_hash_ops, UINT64_TO_PTR(id), req);
        if (r < 0)
                return log_debug_errno(r, "OVSDB RPC: failed to register in-flight request: %m");

        TAKE_PTR(req);

        r = sd_json_buildo(
                        &message,
                        SD_JSON_BUILD_PAIR_STRING("method", method),
                        SD_JSON_BUILD_PAIR("params", SD_JSON_BUILD_VARIANT(params)),
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", id));
        if (r < 0) {
                ovsdb_rpc_request_free(hashmap_remove(rpc->in_flight, UINT64_TO_PTR(id)));
                return log_debug_errno(r, "OVSDB RPC: failed to build request message: %m");
        }

        *ret_message = TAKE_PTR(message);
        if (ret_id)
                *ret_id = id;
        return 0;
}

void ovsdb_rpc_cancel_request(OVSDBRpcLayer *rpc, uint64_t id) {
        assert(rpc);

        ovsdb_rpc_request_free(hashmap_remove(rpc->in_flight, UINT64_TO_PTR(id)));
}

int ovsdb_rpc_layer_dispatch(
                OVSDBRpcLayer *rpc,
                OVSDBClient *client,
                sd_json_variant *message,
                ovsdb_notify_cb_t notify_cb,
                void *notify_userdata) {

        sd_json_variant *id_variant, *method_variant;

        assert(rpc);
        assert(message);

        if (!sd_json_variant_is_object(message))
                return log_debug_errno(SYNTHETIC_ERRNO(EBADMSG), "OVSDB RPC: incoming message is not an object");

        id_variant = sd_json_variant_by_key(message, "id");
        method_variant = sd_json_variant_by_key(message, "method");

        /* Server-originated notification: has "method" key and null (or absent) id.
         * Echo requests (method + non-null id) are handled in ovsdb-client.c dispatch
         * loop before reaching here. */
        if (method_variant && sd_json_variant_is_string(method_variant) &&
            (!id_variant || sd_json_variant_is_null(id_variant))) {
                const char *method;
                sd_json_variant *params;

                method = sd_json_variant_string(method_variant);
                params = sd_json_variant_by_key(message, "params");

                log_debug("OVSDB RPC: received notification method='%s'", method);

                if (notify_cb)
                        return notify_cb(client, method, params, notify_userdata);

                return 0;
        }

        /* Reply: has unsigned id */
        if (id_variant && sd_json_variant_is_unsigned(id_variant)) {
                _cleanup_free_ OVSDBRpcRequest *req = NULL;
                sd_json_variant *result, *error;
                uint64_t id;

                id = sd_json_variant_unsigned(id_variant);

                req = hashmap_remove(rpc->in_flight, UINT64_TO_PTR(id));
                if (!req)
                        return log_debug_errno(SYNTHETIC_ERRNO(ENOENT),
                                               "OVSDB RPC: received reply for unknown id=%" PRIu64, id);

                result = sd_json_variant_by_key(message, "result");
                error = sd_json_variant_by_key(message, "error");

                /* Normalize JSON null to C NULL */
                if (result && sd_json_variant_is_null(result))
                        result = NULL;
                if (error && sd_json_variant_is_null(error))
                        error = NULL;

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

        if (!rpc)
                return;

        while ((req = hashmap_steal_first(rpc->in_flight))) {
                if (req->cb)
                        (void) req->cb(client, /* result= */ NULL, synthetic_error, req->userdata);

                ovsdb_rpc_request_free(req);
        }
}
