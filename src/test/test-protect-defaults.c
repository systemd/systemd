/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "load-fragment.h"
#include "namespace.h"
#include "tests.h"

TEST(private_tmp_from_string) {
        /* Enum string values */
        assert_se(private_tmp_from_string("no") == PRIVATE_TMP_NO);
        assert_se(private_tmp_from_string("connected") == PRIVATE_TMP_CONNECTED);
        assert_se(private_tmp_from_string("disconnected") == PRIVATE_TMP_DISCONNECTED);

        /* Boolean compatibility (WITH_BOOLEAN maps true -> CONNECTED) */
        assert_se(private_tmp_from_string("yes") == PRIVATE_TMP_CONNECTED);
        assert_se(private_tmp_from_string("true") == PRIVATE_TMP_CONNECTED);
        assert_se(private_tmp_from_string("on") == PRIVATE_TMP_CONNECTED);
        assert_se(private_tmp_from_string("1") == PRIVATE_TMP_CONNECTED);

        /* Boolean false variants */
        assert_se(private_tmp_from_string("false") == PRIVATE_TMP_NO);
        assert_se(private_tmp_from_string("off") == PRIVATE_TMP_NO);
        assert_se(private_tmp_from_string("0") == PRIVATE_TMP_NO);

        /* Invalid values */
        assert_se(private_tmp_from_string("invalid") < 0);
        assert_se(private_tmp_from_string("") < 0);
}

TEST(private_tmp_to_string) {
        ASSERT_STREQ(private_tmp_to_string(PRIVATE_TMP_NO), "no");
        ASSERT_STREQ(private_tmp_to_string(PRIVATE_TMP_CONNECTED), "connected");
        ASSERT_STREQ(private_tmp_to_string(PRIVATE_TMP_DISCONNECTED), "disconnected");
}

TEST(protect_home_from_string) {
        /* Enum string values */
        assert_se(protect_home_from_string("no") == PROTECT_HOME_NO);
        assert_se(protect_home_from_string("yes") == PROTECT_HOME_YES);
        assert_se(protect_home_from_string("read-only") == PROTECT_HOME_READ_ONLY);
        assert_se(protect_home_from_string("tmpfs") == PROTECT_HOME_TMPFS);

        /* Boolean compatibility (WITH_BOOLEAN maps true -> YES) */
        assert_se(protect_home_from_string("true") == PROTECT_HOME_YES);
        assert_se(protect_home_from_string("on") == PROTECT_HOME_YES);
        assert_se(protect_home_from_string("1") == PROTECT_HOME_YES);

        /* Boolean false variants */
        assert_se(protect_home_from_string("false") == PROTECT_HOME_NO);
        assert_se(protect_home_from_string("off") == PROTECT_HOME_NO);
        assert_se(protect_home_from_string("0") == PROTECT_HOME_NO);

        /* Invalid values */
        assert_se(protect_home_from_string("invalid") < 0);
        assert_se(protect_home_from_string("") < 0);
}

TEST(protect_home_to_string) {
        ASSERT_STREQ(protect_home_to_string(PROTECT_HOME_NO), "no");
        ASSERT_STREQ(protect_home_to_string(PROTECT_HOME_YES), "yes");
        ASSERT_STREQ(protect_home_to_string(PROTECT_HOME_READ_ONLY), "read-only");
        ASSERT_STREQ(protect_home_to_string(PROTECT_HOME_TMPFS), "tmpfs");
}

TEST(config_parse_private_tmp_values) {
        PrivateTmp result = PRIVATE_TMP_NO;

        /* Test parsing "yes" -> CONNECTED */
        ASSERT_OK(config_parse_private_tmp("unit", "filename", 1, "section", 1,
                                           "PrivateTmp", 0, "yes", &result, NULL));
        assert_se(result == PRIVATE_TMP_CONNECTED);

        /* Test parsing "no" -> NO */
        ASSERT_OK(config_parse_private_tmp("unit", "filename", 1, "section", 1,
                                           "PrivateTmp", 0, "no", &result, NULL));
        assert_se(result == PRIVATE_TMP_NO);

        /* Test parsing "connected" -> CONNECTED */
        ASSERT_OK(config_parse_private_tmp("unit", "filename", 1, "section", 1,
                                           "PrivateTmp", 0, "connected", &result, NULL));
        assert_se(result == PRIVATE_TMP_CONNECTED);

        /* Test parsing "disconnected" -> DISCONNECTED */
        ASSERT_OK(config_parse_private_tmp("unit", "filename", 1, "section", 1,
                                           "PrivateTmp", 0, "disconnected", &result, NULL));
        assert_se(result == PRIVATE_TMP_DISCONNECTED);

        /* Test parsing "true" -> CONNECTED (boolean compat) */
        ASSERT_OK(config_parse_private_tmp("unit", "filename", 1, "section", 1,
                                           "PrivateTmp", 0, "true", &result, NULL));
        assert_se(result == PRIVATE_TMP_CONNECTED);
}

TEST(config_parse_protect_home_values) {
        ProtectHome result = PROTECT_HOME_NO;

        /* Test parsing "yes" -> YES */
        ASSERT_OK(config_parse_protect_home("unit", "filename", 1, "section", 1,
                                            "ProtectHome", 0, "yes", &result, NULL));
        assert_se(result == PROTECT_HOME_YES);

        /* Test parsing "no" -> NO */
        ASSERT_OK(config_parse_protect_home("unit", "filename", 1, "section", 1,
                                            "ProtectHome", 0, "no", &result, NULL));
        assert_se(result == PROTECT_HOME_NO);

        /* Test parsing "read-only" -> READ_ONLY */
        ASSERT_OK(config_parse_protect_home("unit", "filename", 1, "section", 1,
                                            "ProtectHome", 0, "read-only", &result, NULL));
        assert_se(result == PROTECT_HOME_READ_ONLY);

        /* Test parsing "tmpfs" -> TMPFS */
        ASSERT_OK(config_parse_protect_home("unit", "filename", 1, "section", 1,
                                            "ProtectHome", 0, "tmpfs", &result, NULL));
        assert_se(result == PROTECT_HOME_TMPFS);

        /* Test parsing "true" -> YES (boolean compat) */
        ASSERT_OK(config_parse_protect_home("unit", "filename", 1, "section", 1,
                                            "ProtectHome", 0, "true", &result, NULL));
        assert_se(result == PROTECT_HOME_YES);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
