/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "emergency-action.h"
#include "tests.h"

TEST(parse_emergency_action) {
        EmergencyAction x;

        assert_se(parse_emergency_action("none", false, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_NONE);
        assert_se(parse_emergency_action("reboot", false, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("reboot-force", false, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("reboot-immediate", false, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("poweroff", false, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("poweroff-force", false, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("poweroff-immediate", false, &x) == -EOPNOTSUPP);
        assert_se(x == EMERGENCY_ACTION_NONE);
        assert_se(parse_emergency_action("exit", false, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_EXIT);
        assert_se(parse_emergency_action("exit-force", false, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_EXIT_FORCE);
        assert_se(parse_emergency_action("exit-forcee", false, &x) == -EINVAL);

        assert_se(parse_emergency_action("none", true, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_NONE);
        assert_se(parse_emergency_action("reboot", true, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_REBOOT);
        assert_se(parse_emergency_action("reboot-force", true, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_REBOOT_FORCE);
        assert_se(parse_emergency_action("reboot-immediate", true, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_REBOOT_IMMEDIATE);
        assert_se(parse_emergency_action("poweroff", true, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_POWEROFF);
        assert_se(parse_emergency_action("poweroff-force", true, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_POWEROFF_FORCE);
        assert_se(parse_emergency_action("poweroff-immediate", true, &x) == 0);
        assert_se(parse_emergency_action("exit", true, &x) == 0);
        assert_se(parse_emergency_action("exit-force", true, &x) == 0);
        assert_se(parse_emergency_action("exit-forcee", true, &x) == -EINVAL);
        assert_se(x == EMERGENCY_ACTION_EXIT_FORCE);
}

DEFINE_TEST_MAIN(LOG_INFO);
