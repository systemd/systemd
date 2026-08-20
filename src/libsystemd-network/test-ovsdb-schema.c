/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "tests.h"
#include "ovsdb/ovsdb-schema.h"

TEST(schema_validate_minimal_ok) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;

        ASSERT_OK(sd_json_build(&schema,
                SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_STRING("name", "Open_vSwitch"),
                        SD_JSON_BUILD_PAIR_STRING("version", "8.8.0"),
                        SD_JSON_BUILD_PAIR("tables",
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR("Open_vSwitch", SD_JSON_BUILD_EMPTY_OBJECT),
                                        SD_JSON_BUILD_PAIR("Bridge", SD_JSON_BUILD_EMPTY_OBJECT),
                                        SD_JSON_BUILD_PAIR("Port", SD_JSON_BUILD_EMPTY_OBJECT),
                                        SD_JSON_BUILD_PAIR("Interface", SD_JSON_BUILD_EMPTY_OBJECT))))));

        ASSERT_OK(ovsdb_schema_validate(schema));
        ASSERT_STREQ(ovsdb_schema_version(schema), "8.8.0");
}

TEST(schema_validate_missing_bridge_table) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;

        ASSERT_OK(sd_json_build(&schema,
                SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR("tables",
                                SD_JSON_BUILD_OBJECT(
                                        SD_JSON_BUILD_PAIR("Open_vSwitch", SD_JSON_BUILD_EMPTY_OBJECT),
                                        SD_JSON_BUILD_PAIR("Port", SD_JSON_BUILD_EMPTY_OBJECT),
                                        SD_JSON_BUILD_PAIR("Interface", SD_JSON_BUILD_EMPTY_OBJECT))))));

        ASSERT_ERROR(ovsdb_schema_validate(schema), EPROTONOSUPPORT);
}

TEST(schema_validate_not_an_object) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;

        ASSERT_OK(sd_json_build(&schema,
                SD_JSON_BUILD_ARRAY(
                        SD_JSON_BUILD_STRING("foo"))));

        ASSERT_ERROR(ovsdb_schema_validate(schema), EBADMSG);
}

TEST(schema_validate_null) {
        ASSERT_ERROR(ovsdb_schema_validate(NULL), EINVAL);
}

TEST(schema_validate_missing_tables_key) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *schema = NULL;

        ASSERT_OK(sd_json_build(&schema,
                SD_JSON_BUILD_OBJECT(
                        SD_JSON_BUILD_PAIR_STRING("name", "Open_vSwitch"))));

        ASSERT_ERROR(ovsdb_schema_validate(schema), EBADMSG);
}

TEST(schema_version_returns_null_on_invalid) {
        ASSERT_NULL(ovsdb_schema_version(NULL));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
