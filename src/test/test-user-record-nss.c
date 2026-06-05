/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <pwd.h>
#include <string.h>
#include "sd-json.h"

#include "strv.h"
#include "tests.h"
#include "user-record.h"
#include "user-record-nss.h"

TEST(nss_user_alias) {
        static const struct passwd pwd = {
                .pw_name = (char*) "testuser",
                .pw_uid = 1000,
                .pw_gid = 1000,
                .pw_gecos = (char*) "testuser",
                .pw_dir = (char*) "/home/testuser",
                .pw_shell = (char*) "/bin/bash",
        };
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;
        sd_json_variant *aliases;

        ASSERT_OK(nss_passwd_to_user_record(&pwd, NULL, "testuser@example.test", &u));
        ASSERT_TRUE(user_record_matches_user_name(u, "testuser@example.test"));
        ASSERT_TRUE(strv_contains(u->aliases, "testuser@example.test"));

        aliases = ASSERT_NOT_NULL(sd_json_variant_by_key(u->json, "aliases"));
        ASSERT_STREQ(sd_json_variant_string(sd_json_variant_by_index(aliases, 0)), "testuser@example.test");
}

TEST(nss_user_invalid_alias) {
        static const struct passwd pwd = {
                .pw_name = (char*) "testuser",
                .pw_uid = 1000,
                .pw_gid = 1000,
                .pw_gecos = (char*) "testuser",
                .pw_dir = (char*) "/home/testuser",
                .pw_shell = (char*) "/bin/bash",
        };
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;

        ASSERT_OK(nss_passwd_to_user_record(&pwd, NULL, "testuser/bad", &u));
        ASSERT_FALSE(user_record_matches_user_name(u, "testuser/bad"));
        ASSERT_TRUE(strv_isempty(u->aliases));
        ASSERT_NULL(sd_json_variant_by_key(u->json, "aliases"));
}

TEST(nss_user_alias_realm) {
        static const struct passwd pwd = {
                .pw_name = (char*) "testuser",
                .pw_uid = 1000,
                .pw_gid = 1000,
                .pw_gecos = (char*) "testuser",
                .pw_dir = (char*) "/home/testuser",
                .pw_shell = (char*) "/bin/bash",
        };
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;

        ASSERT_OK(nss_passwd_to_user_record(&pwd, NULL, "testuser-short", &u));
        u->realm = ASSERT_NOT_NULL(strdup("example.test"));

        ASSERT_TRUE(user_record_matches_user_name(u, "testuser-short@example.test"));
}

TEST(nss_user_alias_same_as_canonical_noop) {
        static const struct passwd pwd = {
                .pw_name = (char*) "testuser",
                .pw_uid = 1000,
                .pw_gid = 1000,
                .pw_gecos = (char*) "testuser",
                .pw_dir = (char*) "/home/testuser",
                .pw_shell = (char*) "/bin/bash",
        };
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;

        ASSERT_OK(nss_passwd_to_user_record(&pwd, NULL, "testuser", &u));
        ASSERT_TRUE(strv_isempty(u->aliases));
        ASSERT_NULL(sd_json_variant_by_key(u->json, "aliases"));
}

TEST(nss_user_null_alias_noop) {
        static const struct passwd pwd = {
                .pw_name = (char*) "testuser",
                .pw_uid = 1000,
                .pw_gid = 1000,
                .pw_gecos = (char*) "testuser",
                .pw_dir = (char*) "/home/testuser",
                .pw_shell = (char*) "/bin/bash",
        };
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;

        ASSERT_OK(nss_passwd_to_user_record(&pwd, NULL, NULL, &u));
        ASSERT_TRUE(strv_isempty(u->aliases));
        ASSERT_NULL(sd_json_variant_by_key(u->json, "aliases"));
}

TEST(nss_user_alias_fuzzy_match) {
        static const struct passwd pwd = {
                .pw_name = (char*) "canonical",
                .pw_uid = 1000,
                .pw_gid = 1000,
                .pw_gecos = (char*) "canonical",
                .pw_dir = (char*) "/home/canonical",
                .pw_shell = (char*) "/bin/bash",
        };
        _cleanup_(user_record_unrefp) UserRecord *u = NULL;
        UserDBMatch match = USERDB_MATCH_NULL;

        ASSERT_OK(nss_passwd_to_user_record(&pwd, NULL, "external-login", &u));
        match.fuzzy_names = ASSERT_NOT_NULL(strv_new("ternal"));

        ASSERT_TRUE(user_record_match(u, &match));
        userdb_match_done(&match);
}

DEFINE_TEST_MAIN(LOG_INFO);
