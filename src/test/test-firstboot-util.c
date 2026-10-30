/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "firstboot-util.h"
#include "tests.h"

TEST(firstboot_mode_from_string) {
        ASSERT_EQ(firstboot_mode_from_string("yes"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("1"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("on"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("true"), FIRSTBOOT_INTERACTIVE);
        ASSERT_EQ(firstboot_mode_from_string("interactive"), FIRSTBOOT_INTERACTIVE);

        ASSERT_EQ(firstboot_mode_from_string("no"), FIRSTBOOT_NO);
        ASSERT_EQ(firstboot_mode_from_string("0"), FIRSTBOOT_NO);
        ASSERT_EQ(firstboot_mode_from_string("off"), FIRSTBOOT_NO);
        ASSERT_EQ(firstboot_mode_from_string("false"), FIRSTBOOT_NO);

        ASSERT_EQ(firstboot_mode_from_string("headless"), FIRSTBOOT_HEADLESS);

        ASSERT_EQ(firstboot_mode_from_string(""), _FIRSTBOOT_MODE_INVALID);
        ASSERT_EQ(firstboot_mode_from_string(NULL), _FIRSTBOOT_MODE_INVALID);
        ASSERT_EQ(firstboot_mode_from_string("Headless"), _FIRSTBOOT_MODE_INVALID);
        ASSERT_EQ(firstboot_mode_from_string("maybe"), _FIRSTBOOT_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_INFO);
