/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cgroup.h"
#include "emergency-action.h"
#include "execute.h"
#include "log.h"
#include "tests.h"
#include "test-varlink-idl-util.h"
#include "unit.h"
#include "varlink-idl-common.h"
#include "varlink-io.systemd.Manager.h"

TEST(manager_enums_idl) {
        /* ManagerContext enums */
        TEST_IDL_ENUM(LogTarget, log_target, vl_type_LogTarget);
        TEST_IDL_ENUM(OOMPolicy, oom_policy, vl_type_OOMPolicy);

        /* ExecOutput values like "kmsg+console" contain '+' which becomes '_' via underscorify,
         * but dashify won't restore it, so from_string round-trip fails. Test to_string direction only. */
        TEST_IDL_ENUM_TO_STRING(ExecOutput, exec_output, vl_type_ExecOutputType);
        TEST_IDL_ENUM(CGroupPressureWatch, cgroup_pressure_watch, vl_type_CGroupPressureWatch);
        TEST_IDL_ENUM(EmergencyAction, emergency_action, vl_type_EmergencyAction);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
