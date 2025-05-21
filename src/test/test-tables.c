/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-device.h"

#include "architecture.h"
#include "automount.h"
#include "cgroup.h"
#include "cgroup-util.h"
#include "compress.h"
#include "condition.h"
#include "confidential-virt.h"
#include "device-private.h"
#include "discover-image.h"
#include "execute.h"
#include "gpt.h"
#include "import-util.h"
#include "install.h"
#include "job.h"
#include "kill.h"
#include "locale-util.h"
#include "log.h"
#include "manager.h"
#include "mount.h"
#include "netif-naming-scheme.h"
#include "output-mode.h"
#include "path.h"
#include "resolve-util.h"
#include "scope.h"
#include "service.h"
#include "show-status.h"
#include "socket.h"
#include "socket-util.h"
#include "swap.h"
#include "test-tables.h"
#include "tests.h"
#include "timer.h"
#include "unit.h"
#include "unit-name.h"
#include "virt.h"

int main(int argc, char **argv) {
        test_setup_logging(LOG_DEBUG);

        test_table(Architecture, architecture, ARCHITECTURE);
        test_table(ConditionType, assert_type, CONDITION_TYPE);
        test_table(AutomountResult, automount_result, AUTOMOUNT_RESULT);
        test_table(AutomountState, automount_state, AUTOMOUNT_STATE);
        test_table(CGroupController, cgroup_controller, CGROUP_CONTROLLER);
        test_table(CGroupDevicePolicy, cgroup_device_policy, CGROUP_DEVICE_POLICY);
        test_table(CGroupIOLimitType, cgroup_io_limit_type, CGROUP_IO_LIMIT_TYPE);
        test_table(CollectMode, collect_mode, COLLECT_MODE);
        test_table(ConditionResult, condition_result, CONDITION_RESULT);
        test_table(ConditionType, condition_type, CONDITION_TYPE);
        test_table(ConfidentialVirtualization, confidential_virtualization, CONFIDENTIAL_VIRTUALIZATION);
        test_table(sd_device_action_t, device_action, SD_DEVICE_ACTION);
        test_table(DeviceState, device_state, DEVICE_STATE);
        test_table(DnsOverTlsMode, dns_over_tls_mode, DNS_OVER_TLS_MODE);
        test_table(DnssecMode, dnssec_mode, DNSSEC_MODE);
        test_table(EmergencyAction, emergency_action, EMERGENCY_ACTION);
        test_table(ExecDirectoryType, exec_directory_type, EXEC_DIRECTORY_TYPE);
        test_table(ExecInput, exec_input, EXEC_INPUT);
        test_table(ExecKeyringMode, exec_keyring_mode, EXEC_KEYRING_MODE);
        test_table(ExecOutput, exec_output, EXEC_OUTPUT);
        test_table(ExecPreserveMode, exec_preserve_mode, EXEC_PRESERVE_MODE);
        test_table(ExecUtmpMode, exec_utmp_mode, EXEC_UTMP_MODE);
        test_table(ImageType, image_type, IMAGE_TYPE);
        test_table(ImportVerify, import_verify, IMPORT_VERIFY);
        test_table(JobMode, job_mode, JOB_MODE);
        test_table(JobResult, job_result, JOB_RESULT);
        test_table(JobState, job_state, JOB_STATE);
        test_table(JobType, job_type, JOB_TYPE);
        test_table(KillMode, kill_mode, KILL_MODE);
        test_table(KillWhom, kill_whom, KILL_WHOM);
        test_table(LocaleVariable, locale_variable, VARIABLE_LC);
        test_table(LogTarget, log_target, LOG_TARGET);
        test_table(ManagedOOMMode, managed_oom_mode, MANAGED_OOM_MODE);
        test_table(ManagedOOMPreference, managed_oom_preference, MANAGED_OOM_PREFERENCE);
        test_table(ManagerState, manager_state, MANAGER_STATE);
        test_table(ManagerTimestamp, manager_timestamp, MANAGER_TIMESTAMP);
        test_table(MountExecCommand, mount_exec_command, MOUNT_EXEC_COMMAND);
        test_table(MountResult, mount_result, MOUNT_RESULT);
        test_table(MountState, mount_state, MOUNT_STATE);
        test_table(NamePolicy, name_policy, NAMEPOLICY);
        test_table(NotifyAccess, notify_access, NOTIFY_ACCESS);
        test_table(NotifyState, notify_state, NOTIFY_STATE);
        test_table(OutputMode, output_mode, OUTPUT_MODE);
        test_table(PartitionDesignator, partition_designator, PARTITION_DESIGNATOR);
        test_table(PathResult, path_result, PATH_RESULT);
        test_table(PathState, path_state, PATH_STATE);
        test_table(PathType, path_type, PATH_TYPE);
        test_table(ProtectHome, protect_home, PROTECT_HOME);
        test_table(ProtectSystem, protect_system, PROTECT_SYSTEM);
        test_table(ResolveSupport, resolve_support, RESOLVE_SUPPORT);
        test_table(int, rlimit, RLIMIT);
        test_table(ScopeResult, scope_result, SCOPE_RESULT);
        test_table(ScopeState, scope_state, SCOPE_STATE);
        test_table(ServiceExecCommand, service_exec_command, SERVICE_EXEC_COMMAND);
        test_table(ServiceRestart, service_restart, SERVICE_RESTART);
        test_table(ServiceRestartMode, service_restart_mode, SERVICE_RESTART_MODE);
        test_table(ServiceResult, service_result, SERVICE_RESULT);
        test_table(ServiceState, service_state, SERVICE_STATE);
        test_table(ServiceType, service_type, SERVICE_TYPE);
        test_table(ShowStatus, show_status, SHOW_STATUS);
        test_table(SliceState, slice_state, SLICE_STATE);
        test_table(SocketAddressBindIPv6Only, socket_address_bind_ipv6_only, SOCKET_ADDRESS_BIND_IPV6_ONLY);
        test_table(SocketExecCommand, socket_exec_command, SOCKET_EXEC_COMMAND);
        test_table(SocketResult, socket_result, SOCKET_RESULT);
        test_table(SocketState, socket_state, SOCKET_STATE);
        test_table(SwapExecCommand, swap_exec_command, SWAP_EXEC_COMMAND);
        test_table(SwapResult, swap_result, SWAP_RESULT);
        test_table(SwapState, swap_state, SWAP_STATE);
        test_table(TargetState, target_state, TARGET_STATE);
        test_table(TimerBase, timer_base, TIMER_BASE);
        test_table(TimerResult, timer_result, TIMER_RESULT);
        test_table(TimerState, timer_state, TIMER_STATE);
        test_table(UnitActiveState, unit_active_state, UNIT_ACTIVE_STATE);
        test_table(UnitDependency, unit_dependency, UNIT_DEPENDENCY);
        test_table(InstallChangeType, install_change_type, INSTALL_CHANGE_TYPE);
        test_table(UnitFilePresetMode, unit_file_preset_mode, UNIT_FILE_PRESET_MODE);
        test_table(UnitFileState, unit_file_state, UNIT_FILE_STATE);
        test_table(UnitLoadState, unit_load_state, UNIT_LOAD_STATE);
        test_table(UnitType, unit_type, UNIT_TYPE);
        test_table(Virtualization, virtualization, VIRTUALIZATION);
        test_table(Compression, compression, COMPRESSION);

        assert_cc(sizeof(sd_device_action_t) == sizeof(int64_t));

        return EXIT_SUCCESS;
}
