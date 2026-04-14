/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "tests.h"
#include "ovsdb/ovsdb-rpc.h"

static int reply_cb_call_count = 0;
static sd_json_variant *reply_cb_last_result = NULL;
static sd_json_variant *reply_cb_last_error = NULL;

static int notify_cb_call_count = 0;
static const char *notify_cb_last_method = NULL;
static sd_json_variant *notify_cb_last_params = NULL;

static void reset_reply_state(void) {
        reply_cb_call_count = 0;
        reply_cb_last_result = NULL;
        reply_cb_last_error = NULL;
}

static void reset_notify_state(void) {
        notify_cb_call_count = 0;
        notify_cb_last_method = NULL;
        notify_cb_last_params = NULL;
}

static int test_reply_cb(
                OVSDBClient *client,
                sd_json_variant *result,
                sd_json_variant *error,
                void *userdata) {

        reply_cb_call_count++;
        reply_cb_last_result = result;
        reply_cb_last_error = error;
        return 0;
}

static int test_notify_cb(
                OVSDBClient *client,
                const char *method,
                sd_json_variant *params,
                void *userdata) {

        notify_cb_call_count++;
        notify_cb_last_method = method;
        notify_cb_last_params = params;
        return 0;
}

TEST(rpc_build_request_assigns_id) {
        OVSDBRpcLayer rpc;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *message = NULL;
        sd_json_variant *id_variant;

        ovsdb_rpc_layer_init(&rpc);

        ASSERT_OK(sd_json_build(&params,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("Open_vSwitch"))));

        ASSERT_OK(ovsdb_rpc_build_request(
                        &rpc,
                        "get_schema",
                        params,
                        test_reply_cb,
                        /* userdata= */ NULL,
                        &message,
                        /* ret_id= */ NULL));

        ASSERT_NOT_NULL(message);

        id_variant = sd_json_variant_by_key(message, "id");
        ASSERT_NOT_NULL(id_variant);
        ASSERT_TRUE(sd_json_variant_is_unsigned(id_variant));
        ASSERT_EQ(sd_json_variant_unsigned(id_variant), 1u);

        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(message, "method")), "get_schema");

        ovsdb_rpc_layer_done(&rpc);
}

TEST(rpc_dispatch_routes_reply) {
        OVSDBRpcLayer rpc;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *message = NULL, *reply = NULL;

        ovsdb_rpc_layer_init(&rpc);
        reset_reply_state();

        ASSERT_OK(sd_json_build(&params,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("Open_vSwitch"))));

        ASSERT_OK(ovsdb_rpc_build_request(
                        &rpc,
                        "get_schema",
                        params,
                        test_reply_cb,
                        /* userdata= */ NULL,
                        &message,
                        /* ret_id= */ NULL));

        /* Build a fake reply */
        ASSERT_OK(sd_json_buildo(
                        &reply,
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", 1),
                        SD_JSON_BUILD_PAIR("result",
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR_STRING("version", "8.8.0"))),
                        SD_JSON_BUILD_PAIR("error", SD_JSON_BUILD_NULL)));

        ASSERT_OK(ovsdb_rpc_layer_dispatch(
                        &rpc,
                        /* client= */ NULL,
                        reply,
                        /* notify_cb= */ NULL,
                        /* notify_userdata= */ NULL));

        ASSERT_EQ(reply_cb_call_count, 1);
        ASSERT_NOT_NULL(reply_cb_last_result);
        ASSERT_NULL(reply_cb_last_error);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(reply_cb_last_result, "version")), "8.8.0");

        ovsdb_rpc_layer_done(&rpc);
}

TEST(rpc_dispatch_routes_notification) {
        OVSDBRpcLayer rpc;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *notification = NULL;

        ovsdb_rpc_layer_init(&rpc);
        reset_notify_state();

        ASSERT_OK(sd_json_buildo(
                        &notification,
                        SD_JSON_BUILD_PAIR_STRING("method", "update2"),
                        SD_JSON_BUILD_PAIR("params",
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("networkd"),
                                        SD_JSON_BUILD_EMPTY_OBJECT)),
                        SD_JSON_BUILD_PAIR("id", SD_JSON_BUILD_NULL)));

        ASSERT_OK(ovsdb_rpc_layer_dispatch(
                        &rpc,
                        /* client= */ NULL,
                        notification,
                        test_notify_cb,
                        /* notify_userdata= */ NULL));

        ASSERT_EQ(notify_cb_call_count, 1);
        ASSERT_STREQ(notify_cb_last_method, "update2");
        ASSERT_NOT_NULL(notify_cb_last_params);

        ovsdb_rpc_layer_done(&rpc);
}

TEST(rpc_dispatch_unknown_id) {
        OVSDBRpcLayer rpc;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;

        ovsdb_rpc_layer_init(&rpc);

        ASSERT_OK(sd_json_buildo(
                        &reply,
                        SD_JSON_BUILD_PAIR_UNSIGNED("id", 999),
                        SD_JSON_BUILD_PAIR_STRING("result", "ok"),
                        SD_JSON_BUILD_PAIR("error", SD_JSON_BUILD_NULL)));

        ASSERT_ERROR(ovsdb_rpc_layer_dispatch(
                        &rpc,
                        /* client= */ NULL,
                        reply,
                        /* notify_cb= */ NULL,
                        /* notify_userdata= */ NULL), ENOENT);

        ovsdb_rpc_layer_done(&rpc);
}

TEST(rpc_cancel_all) {
        OVSDBRpcLayer rpc;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *params = NULL, *msg1 = NULL, *msg2 = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *synthetic_error = NULL;

        ovsdb_rpc_layer_init(&rpc);
        reset_reply_state();

        ASSERT_OK(sd_json_build(&params,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("Open_vSwitch"))));

        ASSERT_OK(ovsdb_rpc_build_request(
                        &rpc,
                        "get_schema",
                        params,
                        test_reply_cb,
                        /* userdata= */ NULL,
                        &msg1,
                        /* ret_id= */ NULL));

        ASSERT_OK(ovsdb_rpc_build_request(
                        &rpc,
                        "list_dbs",
                        params,
                        test_reply_cb,
                        /* userdata= */ NULL,
                        &msg2,
                        /* ret_id= */ NULL));

        ASSERT_OK(sd_json_buildo(
                        &synthetic_error,
                        SD_JSON_BUILD_PAIR_STRING("error", "connection lost")));

        ovsdb_rpc_layer_cancel_all(&rpc, /* client= */ NULL, synthetic_error);

        ASSERT_EQ(reply_cb_call_count, 2);
        ASSERT_NULL(reply_cb_last_result);
        ASSERT_NOT_NULL(reply_cb_last_error);

        ovsdb_rpc_layer_done(&rpc);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
