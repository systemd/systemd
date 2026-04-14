/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "tests.h"
#include "ovsdb/ovsdb-ops.h"

static void assert_json_eq(sd_json_variant *got, const char *expected) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *want = NULL;
        ASSERT_OK(sd_json_parse(expected, /* flags= */ 0, &want, /* reterr_line= */ NULL, /* reterr_column= */ NULL));
        ASSERT_TRUE(sd_json_variant_equal(got, want));
}

TEST(op_insert_minimal) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *row = NULL, *op = NULL;

        ASSERT_OK(sd_json_buildo(&row,
                SD_JSON_BUILD_PAIR_STRING("name", "br0"),
                SD_JSON_BUILD_PAIR_BOOLEAN("stp_enable", false)));

        ASSERT_OK(ovsdb_op_insert("Bridge", /* uuid_name= */ NULL, row, &op));

        assert_json_eq(op,
                "{\"op\":\"insert\",\"table\":\"Bridge\",\"row\":{\"name\":\"br0\",\"stp_enable\":false}}");
}

TEST(op_insert_with_named_uuid) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *row = NULL, *op = NULL;

        ASSERT_OK(sd_json_buildo(&row,
                SD_JSON_BUILD_PAIR_STRING("name", "br0")));

        ASSERT_OK(ovsdb_op_insert("Bridge", "mybr", row, &op));

        assert_json_eq(op,
                "{\"op\":\"insert\",\"table\":\"Bridge\",\"row\":{\"name\":\"br0\"},\"uuid-name\":\"mybr\"}");
}

TEST(op_delete) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL, *op = NULL;

        ASSERT_OK(ovsdb_where_uuid("550e8400-e29b-41d4-a716-446655440000", &where));
        ASSERT_OK(ovsdb_op_delete("Bridge", where, &op));

        assert_json_eq(op,
                "{\"op\":\"delete\",\"table\":\"Bridge\","
                "\"where\":[[\"_uuid\",\"==\",[\"uuid\",\"550e8400-e29b-41d4-a716-446655440000\"]]]}");
}

TEST(op_mutate_set_insert) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL, *mutations = NULL, *op = NULL;

        ASSERT_OK(ovsdb_where_all(&where));

        /* Build a mutations array: [["ports", "insert", ["set", [["named-uuid", "myport"]]]]] */
        ASSERT_OK(sd_json_build(&mutations,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_ARRAY(
                                SD_JSON_BUILD_STRING("ports"),
                                SD_JSON_BUILD_STRING("insert"),
                                SD_JSON_BUILD_ARRAY(
                                        SD_JSON_BUILD_STRING("set"),
                                        SD_JSON_BUILD_ARRAY(
                                                SD_JSON_BUILD_ARRAY(
                                                        SD_JSON_BUILD_STRING("named-uuid"),
                                                        SD_JSON_BUILD_STRING("myport"))))))));

        ASSERT_OK(ovsdb_op_mutate("Bridge", where, mutations, &op));

        assert_json_eq(op,
                "{\"op\":\"mutate\",\"table\":\"Bridge\",\"where\":[],"
                "\"mutations\":[[\"ports\",\"insert\",[\"set\",[[\"named-uuid\",\"myport\"]]]]]}");
}

TEST(op_comment) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *op = NULL;

        ASSERT_OK(ovsdb_op_comment("systemd-networkd adding bridge", &op));

        assert_json_eq(op,
                "{\"op\":\"comment\",\"comment\":\"systemd-networkd adding bridge\"}");
}

TEST(where_uuid_builder) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;

        ASSERT_OK(ovsdb_where_uuid("abcdef01-2345-6789-abcd-ef0123456789", &where));

        assert_json_eq(where,
                "[[\"_uuid\",\"==\",[\"uuid\",\"abcdef01-2345-6789-abcd-ef0123456789\"]]]");
}

TEST(where_all_empty_array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *where = NULL;

        ASSERT_OK(ovsdb_where_all(&where));

        assert_json_eq(where, "[]");
}

DEFINE_TEST_MAIN(LOG_DEBUG);
