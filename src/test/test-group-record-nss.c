/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>
#include <string.h>

#include "sd-json.h"
#include "group-record.h"
#include "strv.h"
#include "tests.h"
#include "user-record-nss.h"

TEST(nss_group_alias) {
        static const struct group grp = {
                .gr_name = (char*) "domain users",
                .gr_gid = 1000,
        };
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        sd_json_variant *aliases;

        ASSERT_OK(nss_group_to_group_record(&grp, NULL, "domain users@example.test", &g));
        ASSERT_TRUE(group_record_matches_group_name(g, "domain users@example.test"));
        ASSERT_TRUE(strv_contains(g->aliases, "domain users@example.test"));

        aliases = ASSERT_NOT_NULL(sd_json_variant_by_key(g->json, "aliases"));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_index(aliases, 0)), "domain users@example.test");
}

TEST(nss_group_invalid_alias) {
        static const struct group grp = {
                .gr_name = (char*) "domain users",
                .gr_gid = 1000,
        };
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;

        ASSERT_OK(nss_group_to_group_record(&grp, NULL, "domain/users", &g));
        ASSERT_FALSE(group_record_matches_group_name(g, "domain/users"));
        ASSERT_TRUE(strv_isempty(g->aliases));
        ASSERT_NULL(sd_json_variant_by_key(g->json, "aliases"));
}

TEST(nss_group_alias_realm) {
        static const struct group grp = {
                .gr_name = (char*) "domain users",
                .gr_gid = 1000,
        };
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;

        ASSERT_OK(nss_group_to_group_record(&grp, NULL, "domain-users", &g));
        g->realm = ASSERT_NOT_NULL(strdup("example.test"));

        ASSERT_TRUE(group_record_matches_group_name(g, "domain-users@example.test"));
}

TEST(nss_group_alias_same_as_canonical_noop) {
        static const struct group grp = {
                .gr_name = (char*) "domain users",
                .gr_gid = 1000,
        };
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;

        ASSERT_OK(nss_group_to_group_record(&grp, NULL, "domain users", &g));
        ASSERT_TRUE(strv_isempty(g->aliases));
        ASSERT_NULL(sd_json_variant_by_key(g->json, "aliases"));
}

TEST(nss_group_null_alias_noop) {
        static const struct group grp = {
                .gr_name = (char*) "domain users",
                .gr_gid = 1000,
        };
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;

        ASSERT_OK(nss_group_to_group_record(&grp, NULL, NULL, &g));
        ASSERT_TRUE(strv_isempty(g->aliases));
        ASSERT_NULL(sd_json_variant_by_key(g->json, "aliases"));
}

TEST(nss_group_alias_fuzzy_match) {
        static const struct group grp = {
                .gr_name = (char*) "canonical group",
                .gr_gid = 1000,
        };
        _cleanup_(group_record_unrefp) GroupRecord *g = NULL;
        UserDBMatch match = USERDB_MATCH_NULL;

        ASSERT_OK(nss_group_to_group_record(&grp, NULL, "external-group", &g));
        match.fuzzy_names = ASSERT_NOT_NULL(strv_new("ternal"));

        ASSERT_TRUE(group_record_match(g, &match));
        userdb_match_done(&match);
}

DEFINE_TEST_MAIN(LOG_INFO);
