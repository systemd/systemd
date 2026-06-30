/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "firstboot-util.h"
#include "tests.h"

TEST(firstboot_mode_from_string) {
        assert_se(firstboot_mode_from_string("yes") == FIRSTBOOT_INTERACTIVE);
        assert_se(firstboot_mode_from_string("1") == FIRSTBOOT_INTERACTIVE);
        assert_se(firstboot_mode_from_string("on") == FIRSTBOOT_INTERACTIVE);
        assert_se(firstboot_mode_from_string("true") == FIRSTBOOT_INTERACTIVE);

        assert_se(firstboot_mode_from_string("no") == FIRSTBOOT_OFF);
        assert_se(firstboot_mode_from_string("0") == FIRSTBOOT_OFF);
        assert_se(firstboot_mode_from_string("off") == FIRSTBOOT_OFF);
        assert_se(firstboot_mode_from_string("false") == FIRSTBOOT_OFF);

        assert_se(firstboot_mode_from_string("headless") == FIRSTBOOT_HEADLESS);

        assert_se(firstboot_mode_from_string("") == _FIRSTBOOT_MODE_INVALID);
        assert_se(firstboot_mode_from_string(NULL) == _FIRSTBOOT_MODE_INVALID);
        assert_se(firstboot_mode_from_string("Headless") == _FIRSTBOOT_MODE_INVALID);
        assert_se(firstboot_mode_from_string("maybe") == _FIRSTBOOT_MODE_INVALID);
}

DEFINE_TEST_MAIN(LOG_INFO);
