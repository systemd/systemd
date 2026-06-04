/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <grp.h>

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

DEFINE_TEST_MAIN(LOG_INFO);
