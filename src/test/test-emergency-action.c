/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "emergency-action.h"
#include "runtime-scope.h"
#include "tests.h"

TEST(parse_emergency_action) {
        EmergencyAction x;

        ASSERT_OK_ZERO(parse_emergency_action("none", RUNTIME_SCOPE_USER, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_NONE);
        ASSERT_ERROR(parse_emergency_action("reboot", RUNTIME_SCOPE_USER, &x), EOPNOTSUPP);
        ASSERT_ERROR(parse_emergency_action("reboot-force", RUNTIME_SCOPE_USER, &x), EOPNOTSUPP);
        ASSERT_ERROR(parse_emergency_action("reboot-immediate", RUNTIME_SCOPE_USER, &x), EOPNOTSUPP);
        ASSERT_ERROR(parse_emergency_action("poweroff", RUNTIME_SCOPE_USER, &x), EOPNOTSUPP);
        ASSERT_ERROR(parse_emergency_action("poweroff-force", RUNTIME_SCOPE_USER, &x), EOPNOTSUPP);
        ASSERT_ERROR(parse_emergency_action("poweroff-immediate", RUNTIME_SCOPE_USER, &x), EOPNOTSUPP);
        ASSERT_EQ(x, EMERGENCY_ACTION_NONE);
        ASSERT_OK_ZERO(parse_emergency_action("exit", RUNTIME_SCOPE_USER, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_EXIT);
        ASSERT_OK_ZERO(parse_emergency_action("exit-force", RUNTIME_SCOPE_USER, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_EXIT_FORCE);
        ASSERT_ERROR(parse_emergency_action("exit-forcee", RUNTIME_SCOPE_USER, &x), EINVAL);

        ASSERT_OK_ZERO(parse_emergency_action("none", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_NONE);
        ASSERT_OK_ZERO(parse_emergency_action("reboot", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_REBOOT);
        ASSERT_OK_ZERO(parse_emergency_action("reboot-force", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_REBOOT_FORCE);
        ASSERT_OK_ZERO(parse_emergency_action("reboot-immediate", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_REBOOT_IMMEDIATE);
        ASSERT_OK_ZERO(parse_emergency_action("poweroff", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_POWEROFF);
        ASSERT_OK_ZERO(parse_emergency_action("poweroff-force", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_EQ(x, EMERGENCY_ACTION_POWEROFF_FORCE);
        ASSERT_OK_ZERO(parse_emergency_action("poweroff-immediate", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_OK_ZERO(parse_emergency_action("exit", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_OK_ZERO(parse_emergency_action("exit-force", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_ERROR(parse_emergency_action("exit-forcee", RUNTIME_SCOPE_SYSTEM, &x), EINVAL);
        ASSERT_EQ(x, EMERGENCY_ACTION_EXIT_FORCE);
        ASSERT_OK_ZERO(parse_emergency_action("kexec", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_OK_ZERO(parse_emergency_action("kexec-force", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_ERROR(parse_emergency_action("kexec-forcee", RUNTIME_SCOPE_SYSTEM, &x), EINVAL);
        ASSERT_EQ(x, EMERGENCY_ACTION_KEXEC_FORCE);
        ASSERT_OK_ZERO(parse_emergency_action("halt", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_OK_ZERO(parse_emergency_action("halt-force", RUNTIME_SCOPE_SYSTEM, &x));
        ASSERT_ERROR(parse_emergency_action("halt-forcee", RUNTIME_SCOPE_SYSTEM, &x), EINVAL);
        ASSERT_EQ(x, EMERGENCY_ACTION_HALT_FORCE);
}

DEFINE_TEST_MAIN(LOG_INFO);
