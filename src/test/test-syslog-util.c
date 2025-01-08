/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "tests.h"
#include "syslog-util.h"

TEST(log_level_to_string) {
        ASSERT_EQ(log_level_from_string("debug"), LOG_DEBUG);
        ASSERT_EQ(log_level_from_string("7"), LOG_DEBUG);
        ASSERT_EQ(log_level_from_string("info"), LOG_INFO);
        ASSERT_EQ(log_level_from_string("emerg"), LOG_EMERG);
        ASSERT_EQ(log_level_from_string("0"), LOG_EMERG);
        ASSERT_ERROR(log_level_from_string("null"), EINVAL);
        ASSERT_ERROR(log_level_from_string("-1"), EINVAL);
        ASSERT_ERROR(log_level_from_string("-8"), EINVAL);
        ASSERT_ERROR(log_level_from_string(""), EINVAL);

        ASSERT_EQ(log_max_level_from_string("debug"), LOG_DEBUG);
        ASSERT_EQ(log_max_level_from_string("7"), LOG_DEBUG);
        ASSERT_EQ(log_max_level_from_string("info"), LOG_INFO);
        ASSERT_EQ(log_max_level_from_string("emerg"), LOG_EMERG);
        ASSERT_EQ(log_max_level_from_string("0"), LOG_EMERG);
        ASSERT_EQ(log_max_level_from_string("null"), LOG_NULL);
        ASSERT_EQ(log_max_level_from_string("-1"), LOG_NULL);
        ASSERT_EQ(log_max_level_from_string("-8"), LOG_NULL);
        ASSERT_ERROR(log_level_from_string(""), EINVAL);
}

DEFINE_TEST_MAIN(LOG_INFO);
