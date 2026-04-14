/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-id128.h"
#include "sd-json.h"

#include "tests.h"
#include "ovsdb/ovsdb-monitor.h"

/* OVSDB row UUIDs are real RFC 4122 UUIDs; the monitor parses them into sd_id128_t.
 * Use distinct real UUIDs as both JSON keys and lookup keys. */
#define TEST_UUID_1 "00000000-0000-4000-8000-000000000001"
#define TEST_UUID_2 "00000000-0000-4000-8000-000000000002"
#define TEST_UUID_3 "00000000-0000-4000-8000-000000000003"
#define TEST_UUID_ABSENT "00000000-0000-4000-8000-0000000000ff"

TEST(monitor_apply_initial_one_bridge) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *reply = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"" TEST_UUID_1 "\": {"
                "      \"initial\": {\"name\": \"br0\", \"stp_enable\": false}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &reply, NULL, NULL));

        ASSERT_OK(ovsdb_monitor_apply_initial(m, reply));
        ASSERT_EQ(ovsdb_monitor_count(m, "Bridge"), 1u);

        sd_id128_t u;
        ASSERT_OK(sd_id128_from_string(TEST_UUID_1, &u));
        sd_json_variant *row = ovsdb_monitor_get(m, "Bridge", u);
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
                "    \"" TEST_UUID_2 "\": {"
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
                "    \"" TEST_UUID_2 "\": {"
                "      \"modify\": {\"stp_enable\": true}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &update, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, update));

        sd_id128_t u;
        ASSERT_OK(sd_id128_from_string(TEST_UUID_2, &u));
        sd_json_variant *row = ovsdb_monitor_get(m, "Bridge", u);
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

/* Look up a key in a cached ["map", [["k","v"], ...]] column. */
static const char* test_map_get(sd_json_variant *row, const char *column, const char *key) {
        sd_json_variant *col = sd_json_variant_by_key(row, column);
        if (!col || sd_json_variant_elements(col) != 2)
                return NULL;

        sd_json_variant *pairs = sd_json_variant_by_index(col, 1);
        for (size_t i = 0; i < sd_json_variant_elements(pairs); i++) {
                sd_json_variant *pair = sd_json_variant_by_index(pairs, i);
                sd_json_variant *k = sd_json_variant_by_index(pair, 0);
                sd_json_variant *v = sd_json_variant_by_index(pair, 1);
                if (k && sd_json_variant_is_string(k) && streq(sd_json_variant_string(k), key))
                        return v ? sd_json_variant_string(v) : NULL;
        }
        return NULL;
}

TEST(monitor_apply_update2_modify_map) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        /* Initial row carrying an external_ids map. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *initial = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"" TEST_UUID_2 "\": {"
                "      \"initial\": {"
                "        \"name\": \"br0\","
                "        \"external_ids\": [\"map\", [[\"networkd-managed\", \"true\"], [\"keep\", \"x\"], [\"drop\", \"gone\"], [\"change\", \"old\"]]]"
                "      }"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &initial, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_initial(m, initial));

        /* update2 "modify" for a map column is a *diff*, not the full value: a pair equal to
         * the cached entry deletes the key (drop=gone), a differing pair updates it
         * (change: old→new), and a new key is added (add=fresh). Untouched keys
         * (networkd-managed, keep) must survive. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"" TEST_UUID_2 "\": {"
                "      \"modify\": {"
                "        \"external_ids\": [\"map\", [[\"drop\", \"gone\"], [\"change\", \"new\"], [\"add\", \"fresh\"]]]"
                "      }"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &update, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, update));

        sd_id128_t u;
        ASSERT_OK(sd_id128_from_string(TEST_UUID_2, &u));
        sd_json_variant *row = ovsdb_monitor_get(m, "Bridge", u);
        ASSERT_NOT_NULL(row);

        /* Untouched keys preserved (this is the bug the diff handling fixes: a verbatim
         * replace would have dropped networkd-managed here). */
        ASSERT_STREQ(test_map_get(row, "external_ids", "networkd-managed"), "true");
        ASSERT_STREQ(test_map_get(row, "external_ids", "keep"), "x");
        /* Changed value applied. */
        ASSERT_STREQ(test_map_get(row, "external_ids", "change"), "new");
        /* New key added. */
        ASSERT_STREQ(test_map_get(row, "external_ids", "add"), "fresh");
        /* Matching pair deleted. */
        ASSERT_NULL(test_map_get(row, "external_ids", "drop"));
}

TEST(monitor_apply_update2_delete) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *initial = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"" TEST_UUID_2 "\": {\"initial\": {\"name\": \"br0\"}}"
                "  }"
                "}",
                /* flags= */ 0, &initial, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_initial(m, initial));
        ASSERT_EQ(ovsdb_monitor_count(m, "Bridge"), 1u);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *update = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"" TEST_UUID_2 "\": {\"delete\": {}}"
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
                "    \"" TEST_UUID_3 "\": {"
                "      \"insert\": {\"name\": \"eth0\", \"tag\": 42}"
                "    }"
                "  }"
                "}",
                /* flags= */ 0, &update, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, update));

        ASSERT_EQ(ovsdb_monitor_count(m, "Port"), 1u);

        sd_id128_t u;
        ASSERT_OK(sd_id128_from_string(TEST_UUID_3, &u));
        sd_json_variant *row = ovsdb_monitor_get(m, "Port", u);
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

        sd_id128_t u;
        ASSERT_OK(sd_id128_from_string(TEST_UUID_ABSENT, &u));
        ASSERT_NULL(ovsdb_monitor_get(m, "Bridge", u));
        ASSERT_NULL(ovsdb_monitor_get(m, "NoTable", u));
        ASSERT_NULL(ovsdb_monitor_get(NULL, "Bridge", u));
}

TEST(monitor_get_by_name) {
        _cleanup_(ovsdb_monitor_freep) OVSDBMonitor *m = ovsdb_monitor_new();
        ASSERT_NOT_NULL(m);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *initial = NULL;
        ASSERT_OK(sd_json_parse(
                "{"
                "  \"Bridge\": {"
                "    \"" TEST_UUID_1 "\": {\"initial\": {\"name\": \"br0\"}},"
                "    \"" TEST_UUID_2 "\": {\"initial\": {\"name\": \"br1\"}}"
                "  }"
                "}",
                /* flags= */ 0, &initial, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_initial(m, initial));

        sd_id128_t u1, u2, got;
        ASSERT_OK(sd_id128_from_string(TEST_UUID_1, &u1));
        ASSERT_OK(sd_id128_from_string(TEST_UUID_2, &u2));

        /* Hit: name resolves to the right uuid and row. */
        sd_json_variant *row = NULL;
        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "Bridge", "br0", &got, &row), 1);
        ASSERT_TRUE(sd_id128_equal(got, u1));
        ASSERT_NOT_NULL(row);
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_key(row, "name")), "br0");

        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "Bridge", "br1", &got, NULL), 1);
        ASSERT_TRUE(sd_id128_equal(got, u2));

        /* Miss: unknown name / table / NULL monitor. */
        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "Bridge", "nope", NULL, NULL), 0);
        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "NoTable", "br0", NULL, NULL), 0);
        ASSERT_EQ(ovsdb_monitor_get_by_name(NULL, "Bridge", "br0", NULL, NULL), 0);

        /* Rename via modify: the index must drop the old name and pick up the new one. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *upd = NULL;
        ASSERT_OK(sd_json_parse(
                "{\"Bridge\": {\"" TEST_UUID_1 "\": {\"modify\": {\"name\": \"br0renamed\"}}}}",
                /* flags= */ 0, &upd, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, upd));

        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "Bridge", "br0", NULL, NULL), 0);
        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "Bridge", "br0renamed", &got, NULL), 1);
        ASSERT_TRUE(sd_id128_equal(got, u1));

        /* Delete: the name must disappear from the index. */
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *del = NULL;
        ASSERT_OK(sd_json_parse(
                "{\"Bridge\": {\"" TEST_UUID_2 "\": {\"delete\": null}}}",
                /* flags= */ 0, &del, NULL, NULL));
        ASSERT_OK(ovsdb_monitor_apply_update2(m, del));

        ASSERT_EQ(ovsdb_monitor_get_by_name(m, "Bridge", "br1", NULL, NULL), 0);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
