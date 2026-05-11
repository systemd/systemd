/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "tests.h"
#include "ovsdb/ovsdb-monitor.h"

TEST(monitor_apply_initial_one_bridge) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"aaa-bbb-ccc\": {"
                "      \"initial\": {\"name\": \"br0\", \"stp_enable\": false}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &reply, NULL, NULL));

        ASSERT_OK(ovsdb_monitor_apply_initial(m, reply));
        ASSERT_EQ(ovsdb_monitor_count(m, "Bridge"), 1u);

        sd_json_variant *row = ovsdb_monitor_get(m, "Bridge", "aaa-bbb-ccc");
        ASSERT_NOT_NULL(row);

        sd_json_variant *name = sd_json_variant_by_key(row, "name");
        ASSERT_NOT_NULL(name);
        ASSERT_STREQ(sd_json_variant_string(name), "br0");
}

TEST(monitor_apply_update2_modify) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        /* Apply initial state */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *initial = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"uuid-1\": {"
                "      \"initial\": {\"name\": \"br0\", \"stp_enable\": false, \"flood_vlans\": 100}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &initial, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_initial(m, initial));

        /* Apply modify update */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"uuid-1\": {"
                "      \"modify\": {\"stp_enable\": true}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &update, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, update));

        sd_json_variant *row = ovsdb_monitor_get(m, "Bridge", "uuid-1");
        ASSERT_NOT_NULL(row);

        /* Modified field should be updated */
        sd_json_variant *stp = sd_json_variant_by_key(row, "stp_enable");
        ASSERT_NOT_NULL(stp);
        ASSERT_TRUE(sd_json_variant_boolean(stp));

        /* Unmodified fields should be preserved */
        sd_json_variant *name = sd_json_variant_by_key(row, "name");
        ASSERT_NOT_NULL(name);
        ASSERT_STREQ(sd_json_variant_string(name), "br0");

        sd_json_variant *vlans = sd_json_variant_by_key(row, "flood_vlans");
        ASSERT_NOT_NULL(vlans);
        ASSERT_EQ(sd_json_variant_integer(vlans), 100);
}

TEST(monitor_apply_update2_delete) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *initial = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"uuid-1\": {\"initial\": {\"name\": \"br0\"}}"
                "  }"
                "}",
                /* flags= */ 0, &initial, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_initial(m, initial));
        ASSERT_EQ(ovsdb_monitor_count(m, "Bridge"), 1u);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"uuid-1\": {\"delete\": {}}"
                "  }"
                "}",
                /* flags= */ 0, &update, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, update));
        ASSERT_EQ(ovsdb_monitor_count(m, "Bridge"), 0u);
}

TEST(monitor_apply_update2_insert) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Port\": {"
                "    \"uuid-new\": {"
                "      \"insert\": {\"name\": \"eth0\", \"tag\": 42}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &update, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, update));

        ASSERT_EQ(ovsdb_monitor_count(m, "Port"), 1u);

        sd_json_variant *row = ovsdb_monitor_get(m, "Port", "uuid-new");
        ASSERT_NOT_NULL(row);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(row, "name")), "eth0");
}

TEST(monitor_count_empty_table) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        ASSERT_EQ(ovsdb_monitor_count(m, "NonExistent"), 0u);
}

TEST(monitor_get_nonexistent) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        ASSERT_NULL(ovsdb_monitor_get(m, "Bridge", "no-such-uuid"));
        ASSERT_NULL(ovsdb_monitor_get(m, "NoTable", "no-such-uuid"));
        ASSERT_NULL(ovsdb_monitor_get(NULL, "Bridge", "uuid"));
}

DEFINE_TEST_MAIN(LOG_DEBUG);
