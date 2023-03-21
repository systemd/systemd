/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "emergency-action.h"
#include "tests.h"

TEST(parse_emergency_action) {
        EmergencyAction x;

        assert_se(parse_emergency_action("none", RUNTIME_SCOPE_USER, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_NONE);
        assert_se(parse_emergency_action("reboot", RUNTIME_SCOPE_USER, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("reboot-force", RUNTIME_SCOPE_USER, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("reboot-immediate", RUNTIME_SCOPE_USER, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("poweroff", RUNTIME_SCOPE_USER, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("poweroff-force", RUNTIME_SCOPE_USER, &x) == -EOPNOTSUPP);
        assert_se(parse_emergency_action("poweroff-immediate", RUNTIME_SCOPE_USER, &x) == -EOPNOTSUPP);
        assert_se(x == EMERGENCY_ACTION_NONE);
        assert_se(parse_emergency_action("exit", RUNTIME_SCOPE_USER, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_EXIT);
        assert_se(parse_emergency_action("exit-force", RUNTIME_SCOPE_USER, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_EXIT_FORCE);
        assert_se(parse_emergency_action("exit-forcee", RUNTIME_SCOPE_USER, &x) == -EINVAL);

        assert_se(parse_emergency_action("none", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_NONE);
        assert_se(parse_emergency_action("reboot", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_REBOOT);
        assert_se(parse_emergency_action("reboot-force", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_REBOOT_FORCE);
        assert_se(parse_emergency_action("reboot-immediate", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_REBOOT_IMMEDIATE);
        assert_se(parse_emergency_action("poweroff", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_POWEROFF);
        assert_se(parse_emergency_action("poweroff-force", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(x == EMERGENCY_ACTION_POWEROFF_FORCE);
        assert_se(parse_emergency_action("poweroff-immediate", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(parse_emergency_action("exit", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(parse_emergency_action("exit-force", RUNTIME_SCOPE_SYSTEM, &x) == 0);
        assert_se(parse_emergency_action("exit-forcee", RUNTIME_SCOPE_SYSTEM, &x) == -EINVAL);
        assert_se(x == EMERGENCY_ACTION_EXIT_FORCE);
}

DEFINE_TEST_MAIN(LOG_INFO);
