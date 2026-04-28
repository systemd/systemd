/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "automount.h"
#include "cgroup.h"
#include "ioprio-util.h"
#include "kill.h"
#include "mount.h"
#include "numa-util.h"
#include "process-util.h"
#include "tests.h"
#include "test-varlink-idl-util.h"
#include "unit.h"
#include "varlink-idl-common.h"
#include "varlink-io.systemd.Unit.h"

TEST(unit_enums_idl) {
        /* ExecContext enums */
        TEST_IDL_ENUM(ExecInput, exec_input, vl_type_ExecInputType);
        TEST_IDL_ENUM_TO_STRING(ExecOutput, exec_output, vl_type_ExecOutputType);
        TEST_IDL_ENUM(ExecUtmpMode, exec_utmp_mode, vl_type_ExecUtmpMode);
        TEST_IDL_ENUM(ExecPreserveMode, exec_preserve_mode, vl_type_ExecPreserveMode);
        TEST_IDL_ENUM(ExecKeyringMode, exec_keyring_mode, vl_type_ExecKeyringMode);
        TEST_IDL_ENUM(ExecMemoryTHP, exec_memory_thp, vl_type_MemoryTHP);
        TEST_IDL_ENUM(ProtectProc, protect_proc, vl_type_ProtectProc);
        TEST_IDL_ENUM(ProcSubset, proc_subset, vl_type_ProcSubset);
        TEST_IDL_ENUM(ProtectSystem, protect_system, vl_type_ProtectSystem);
        TEST_IDL_ENUM(ProtectHome, protect_home, vl_type_ProtectHome);
        TEST_IDL_ENUM(PrivateTmp, private_tmp, vl_type_PrivateTmp);
        TEST_IDL_ENUM(PrivateUsers, private_users, vl_type_PrivateUsers);
        TEST_IDL_ENUM(ProtectHostname, protect_hostname, vl_type_ProtectHostname);
        TEST_IDL_ENUM(ProtectControlGroups, protect_control_groups, vl_type_ProtectControlGroups);
        TEST_IDL_ENUM(PrivatePIDs, private_pids, vl_type_PrivatePIDs);
        TEST_IDL_ENUM(PrivateBPF, private_bpf, vl_type_PrivateBPF);

        /* sched_policy table has gaps (SCHED_IDLE=5, SCHED_EXT=7), so only test from_string direction */
        TEST_IDL_ENUM_FROM_STRING(int, sched_policy, vl_type_CPUSchedulingPolicy);
        /* ioprio_class uses _alloc variant for to_string, so only test from_string direction */
        TEST_IDL_ENUM_FROM_STRING(int, ioprio_class, vl_type_IOSchedulingClass);
        TEST_IDL_ENUM(int, mpol, vl_type_NUMAPolicy);

        /* mount_propagation_flag has non-standard from_string API, test manually */
        test_enum_to_string_name("shared", &vl_type_MountPropagationFlag);
        test_enum_to_string_name("slave", &vl_type_MountPropagationFlag);
        test_enum_to_string_name("private", &vl_type_MountPropagationFlag);

        /* KillContext enums */
        TEST_IDL_ENUM(KillMode, kill_mode, vl_type_KillMode);

        /* CGroupContext enums */
        TEST_IDL_ENUM(CGroupDevicePolicy, cgroup_device_policy, vl_type_CGroupDevicePolicy);
        TEST_IDL_ENUM(ManagedOOMMode, managed_oom_mode, vl_type_ManagedOOMMode);
        TEST_IDL_ENUM(ManagedOOMPreference, managed_oom_preference, vl_type_ManagedOOMPreference);
        TEST_IDL_ENUM(CGroupPressureWatch, cgroup_pressure_watch, vl_type_CGroupPressureWatch);
        TEST_IDL_ENUM(CGroupController, cgroup_controller, vl_type_CGroupController);

        /* AutomountRuntime enums */
        TEST_IDL_ENUM(AutomountResult, automount_result, vl_type_AutomountResult);

        /* MountRuntime enums */
        TEST_IDL_ENUM(MountResult, mount_result, vl_type_MountResult);

        /* UnitContext enums */
        TEST_IDL_ENUM(CollectMode, collect_mode, vl_type_CollectMode);
        TEST_IDL_ENUM(EmergencyAction, emergency_action, vl_type_EmergencyAction);
        TEST_IDL_ENUM(JobMode, job_mode, vl_type_JobMode);
}

DEFINE_TEST_MAIN(LOG_DEBUG);
