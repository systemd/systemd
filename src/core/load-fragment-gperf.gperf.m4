%{
#include <stddef.h>
#include "conf-parser.h"
#include "load-fragment.h"
#include "missing.h"
%}
struct ConfigPerfItem;
%null_strings
%language=ANSI-C
%define slot-name section_and_lvalue
%define hash-function-name load_fragment_gperf_hash
%define lookup-function-name load_fragment_gperf_lookup
%readonly-tables
%omit-struct-type
%struct-type
%includes
%%
m4_dnl Define the context options only once
m4_define(`EXEC_CONTEXT_CONFIG_ITEMS',
`$1.WorkingDirectory,            config_parse_unit_path_printf,      0,                             offsetof($1, exec_context.working_directory)
$1.RootDirectory,                config_parse_unit_path_printf,      0,                             offsetof($1, exec_context.root_directory)
$1.User,                         config_parse_unit_string_printf,    0,                             offsetof($1, exec_context.user)
$1.Group,                        config_parse_unit_string_printf,    0,                             offsetof($1, exec_context.group)
$1.SupplementaryGroups,          config_parse_strv,                  0,                             offsetof($1, exec_context.supplementary_groups)
$1.Nice,                         config_parse_exec_nice,             0,                             offsetof($1, exec_context)
$1.OOMScoreAdjust,               config_parse_exec_oom_score_adjust, 0,                             offsetof($1, exec_context)
$1.IOSchedulingClass,            config_parse_exec_io_class,         0,                             offsetof($1, exec_context)
$1.IOSchedulingPriority,         config_parse_exec_io_priority,      0,                             offsetof($1, exec_context)
$1.CPUSchedulingPolicy,          config_parse_exec_cpu_sched_policy, 0,                             offsetof($1, exec_context)
$1.CPUSchedulingPriority,        config_parse_exec_cpu_sched_prio,   0,                             offsetof($1, exec_context)
$1.CPUSchedulingResetOnFork,     config_parse_bool,                  0,                             offsetof($1, exec_context.cpu_sched_reset_on_fork)
$1.CPUAffinity,                  config_parse_exec_cpu_affinity,     0,                             offsetof($1, exec_context)
$1.UMask,                        config_parse_mode,                  0,                             offsetof($1, exec_context.umask)
$1.Environment,                  config_parse_environ,               0,                             offsetof($1, exec_context.environment)
$1.EnvironmentFile,              config_parse_unit_env_file,         0,                             offsetof($1, exec_context.environment_files)
$1.StandardInput,                config_parse_input,                 0,                             offsetof($1, exec_context.std_input)
$1.StandardOutput,               config_parse_output,                0,                             offsetof($1, exec_context.std_output)
$1.StandardError,                config_parse_output,                0,                             offsetof($1, exec_context.std_error)
$1.TTYPath,                      config_parse_unit_path_printf,      0,                             offsetof($1, exec_context.tty_path)
$1.TTYReset,                     config_parse_bool,                  0,                             offsetof($1, exec_context.tty_reset)
$1.TTYVHangup,                   config_parse_bool,                  0,                             offsetof($1, exec_context.tty_vhangup)
$1.TTYVTDisallocate,             config_parse_bool,                  0,                             offsetof($1, exec_context.tty_vt_disallocate)
$1.SyslogIdentifier,             config_parse_unit_string_printf,    0,                             offsetof($1, exec_context.syslog_identifier)
$1.SyslogFacility,               config_parse_log_facility,          0,                             offsetof($1, exec_context.syslog_priority)
$1.SyslogLevel,                  config_parse_log_level,             0,                             offsetof($1, exec_context.syslog_priority)
$1.SyslogLevelPrefix,            config_parse_bool,                  0,                             offsetof($1, exec_context.syslog_level_prefix)
$1.Capabilities,                 config_parse_exec_capabilities,     0,                             offsetof($1, exec_context)
$1.SecureBits,                   config_parse_exec_secure_bits,      0,                             offsetof($1, exec_context)
$1.CapabilityBoundingSet,        config_parse_bounding_set,          0,                             offsetof($1, exec_context.capability_bounding_set_drop)
$1.TimerSlackNSec,               config_parse_nsec,                  0,                             offsetof($1, exec_context.timer_slack_nsec)
$1.NoNewPrivileges,              config_parse_no_new_privileges,     0,                             offsetof($1, exec_context)
m4_ifdef(`HAVE_SECCOMP',
`$1.SystemCallFilter,            config_parse_syscall_filter,        0,                             offsetof($1, exec_context)
$1.SystemCallArchitectures,      config_parse_syscall_archs,         0,                             offsetof($1, exec_context.syscall_archs)
$1.SystemCallErrorNumber,        config_parse_syscall_errno,         0,                             offsetof($1, exec_context)
$1.RestrictAddressFamilies,      config_parse_address_families,      0,                             offsetof($1, exec_context)',
`$1.SystemCallFilter,            config_parse_warn_compat,           DISABLED_CONFIGURATION,        0
$1.SystemCallArchitectures,      config_parse_warn_compat,           DISABLED_CONFIGURATION,        0
$1.SystemCallErrorNumber,        config_parse_warn_compat,           DISABLED_CONFIGURATION,        0
$1.RestrictAddressFamilies,      config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')
$1.LimitCPU,                     config_parse_limit,                 RLIMIT_CPU,                    offsetof($1, exec_context.rlimit)
$1.LimitFSIZE,                   config_parse_limit,                 RLIMIT_FSIZE,                  offsetof($1, exec_context.rlimit)
$1.LimitDATA,                    config_parse_limit,                 RLIMIT_DATA,                   offsetof($1, exec_context.rlimit)
$1.LimitSTACK,                   config_parse_limit,                 RLIMIT_STACK,                  offsetof($1, exec_context.rlimit)
$1.LimitCORE,                    config_parse_limit,                 RLIMIT_CORE,                   offsetof($1, exec_context.rlimit)
$1.LimitRSS,                     config_parse_limit,                 RLIMIT_RSS,                    offsetof($1, exec_context.rlimit)
$1.LimitNOFILE,                  config_parse_limit,                 RLIMIT_NOFILE,                 offsetof($1, exec_context.rlimit)
$1.LimitAS,                      config_parse_limit,                 RLIMIT_AS,                     offsetof($1, exec_context.rlimit)
$1.LimitNPROC,                   config_parse_limit,                 RLIMIT_NPROC,                  offsetof($1, exec_context.rlimit)
$1.LimitMEMLOCK,                 config_parse_limit,                 RLIMIT_MEMLOCK,                offsetof($1, exec_context.rlimit)
$1.LimitLOCKS,                   config_parse_limit,                 RLIMIT_LOCKS,                  offsetof($1, exec_context.rlimit)
$1.LimitSIGPENDING,              config_parse_limit,                 RLIMIT_SIGPENDING,             offsetof($1, exec_context.rlimit)
$1.LimitMSGQUEUE,                config_parse_limit,                 RLIMIT_MSGQUEUE,               offsetof($1, exec_context.rlimit)
$1.LimitNICE,                    config_parse_limit,                 RLIMIT_NICE,                   offsetof($1, exec_context.rlimit)
$1.LimitRTPRIO,                  config_parse_limit,                 RLIMIT_RTPRIO,                 offsetof($1, exec_context.rlimit)
$1.LimitRTTIME,                  config_parse_limit,                 RLIMIT_RTTIME,                 offsetof($1, exec_context.rlimit)
$1.ReadWriteDirectories,         config_parse_namespace_path_strv,   0,                             offsetof($1, exec_context.read_write_dirs)
$1.ReadOnlyDirectories,          config_parse_namespace_path_strv,   0,                             offsetof($1, exec_context.read_only_dirs)
$1.InaccessibleDirectories,      config_parse_namespace_path_strv,   0,                             offsetof($1, exec_context.inaccessible_dirs)
$1.PrivateTmp,                   config_parse_bool,                  0,                             offsetof($1, exec_context.private_tmp)
$1.PrivateNetwork,               config_parse_bool,                  0,                             offsetof($1, exec_context.private_network)
$1.PrivateDevices,               config_parse_bool,                  0,                             offsetof($1, exec_context.private_devices)
$1.ProtectSystem,                config_parse_protect_system,        0,                             offsetof($1, exec_context)
$1.ProtectHome,                  config_parse_protect_home,          0,                             offsetof($1, exec_context)
$1.MountFlags,                   config_parse_exec_mount_flags,      0,                             offsetof($1, exec_context)
$1.Personality,                  config_parse_personality,           0,                             offsetof($1, exec_context.personality)
$1.RuntimeDirectoryMode,         config_parse_mode,                  0,                             offsetof($1, exec_context.runtime_directory_mode)
$1.RuntimeDirectory,             config_parse_runtime_directory,     0,                             offsetof($1, exec_context.runtime_directory)
m4_ifdef(`HAVE_PAM',
`$1.PAMName,                     config_parse_unit_string_printf,    0,                             offsetof($1, exec_context.pam_name)',
`$1.PAMName,                     config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')
$1.IgnoreSIGPIPE,                config_parse_bool,                  0,                             offsetof($1, exec_context.ignore_sigpipe)
$1.UtmpIdentifier,               config_parse_unit_string_printf,    0,                             offsetof($1, exec_context.utmp_id)
$1.UtmpMode,                     config_parse_exec_utmp_mode,        0,                             offsetof($1, exec_context.utmp_mode)
m4_ifdef(`HAVE_SELINUX',
`$1.SELinuxContext,              config_parse_exec_selinux_context,  0,                             offsetof($1, exec_context)',
`$1.SELinuxContext,              config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')
m4_ifdef(`HAVE_APPARMOR',
`$1.AppArmorProfile,             config_parse_exec_apparmor_profile, 0,                             offsetof($1, exec_context)',
`$1.AppArmorProfile,             config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')
m4_ifdef(`HAVE_SMACK',
`$1.SmackProcessLabel,           config_parse_exec_smack_process_label, 0,                          offsetof($1, exec_context)',
`$1.SmackProcessLabel,           config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')'
)m4_dnl
m4_define(`KILL_CONTEXT_CONFIG_ITEMS',
`$1.SendSIGKILL,                 config_parse_bool,                  0,                             offsetof($1, kill_context.send_sigkill)
$1.SendSIGHUP,                   config_parse_bool,                  0,                             offsetof($1, kill_context.send_sighup)
$1.KillMode,                     config_parse_kill_mode,             0,                             offsetof($1, kill_context.kill_mode)
$1.KillSignal,                   config_parse_signal,                0,                             offsetof($1, kill_context.kill_signal)'
)m4_dnl
m4_define(`CGROUP_CONTEXT_CONFIG_ITEMS',
`$1.Slice,                       config_parse_unit_slice,            0,                             0
$1.CPUAccounting,                config_parse_bool,                  0,                             offsetof($1, cgroup_context.cpu_accounting)
$1.CPUShares,                    config_parse_cpu_shares,            0,                             offsetof($1, cgroup_context.cpu_shares)
$1.StartupCPUShares,             config_parse_cpu_shares,            0,                             offsetof($1, cgroup_context.startup_cpu_shares)
$1.CPUQuota,                     config_parse_cpu_quota,             0,                             offsetof($1, cgroup_context)
$1.MemoryAccounting,             config_parse_bool,                  0,                             offsetof($1, cgroup_context.memory_accounting)
$1.MemoryLimit,                  config_parse_memory_limit,          0,                             offsetof($1, cgroup_context)
$1.DeviceAllow,                  config_parse_device_allow,          0,                             offsetof($1, cgroup_context)
$1.DevicePolicy,                 config_parse_device_policy,         0,                             offsetof($1, cgroup_context.device_policy)
$1.BlockIOAccounting,            config_parse_bool,                  0,                             offsetof($1, cgroup_context.blockio_accounting)
$1.BlockIOWeight,                config_parse_blockio_weight,        0,                             offsetof($1, cgroup_context.blockio_weight)
$1.StartupBlockIOWeight,         config_parse_blockio_weight,        0,                             offsetof($1, cgroup_context.startup_blockio_weight)
$1.BlockIODeviceWeight,          config_parse_blockio_device_weight, 0,                             offsetof($1, cgroup_context)
$1.BlockIOReadBandwidth,         config_parse_blockio_bandwidth,     0,                             offsetof($1, cgroup_context)
$1.BlockIOWriteBandwidth,        config_parse_blockio_bandwidth,     0,                             offsetof($1, cgroup_context)
$1.Delegate,                     config_parse_bool,                  0,                             offsetof($1, cgroup_context.delegate)'
)m4_dnl
Unit.Description,                config_parse_unit_string_printf,    0,                             offsetof(Unit, description)
Unit.Documentation,              config_parse_documentation,         0,                             offsetof(Unit, documentation)
Unit.SourcePath,                 config_parse_path,                  0,                             offsetof(Unit, source_path)
Unit.Requires,                   config_parse_unit_deps,             UNIT_REQUIRES,                 0
Unit.RequiresOverridable,        config_parse_unit_deps,             UNIT_REQUIRES_OVERRIDABLE,     0
Unit.Requisite,                  config_parse_unit_deps,             UNIT_REQUISITE,                0
Unit.RequisiteOverridable,       config_parse_unit_deps,             UNIT_REQUISITE_OVERRIDABLE,    0
Unit.Wants,                      config_parse_unit_deps,             UNIT_WANTS,                    0
Unit.BindsTo,                    config_parse_unit_deps,             UNIT_BINDS_TO,                 0
Unit.BindTo,                     config_parse_unit_deps,             UNIT_BINDS_TO,                 0
Unit.Conflicts,                  config_parse_unit_deps,             UNIT_CONFLICTS,                0
Unit.Before,                     config_parse_unit_deps,             UNIT_BEFORE,                   0
Unit.After,                      config_parse_unit_deps,             UNIT_AFTER,                    0
Unit.OnFailure,                  config_parse_unit_deps,             UNIT_ON_FAILURE,               0
Unit.PropagatesReloadTo,         config_parse_unit_deps,             UNIT_PROPAGATES_RELOAD_TO,     0
Unit.PropagateReloadTo,          config_parse_unit_deps,             UNIT_PROPAGATES_RELOAD_TO,     0
Unit.ReloadPropagatedFrom,       config_parse_unit_deps,             UNIT_RELOAD_PROPAGATED_FROM,   0
Unit.PropagateReloadFrom,        config_parse_unit_deps,             UNIT_RELOAD_PROPAGATED_FROM,   0
Unit.PartOf,                     config_parse_unit_deps,             UNIT_PART_OF,                  0
Unit.JoinsNamespaceOf,           config_parse_unit_deps,             UNIT_JOINS_NAMESPACE_OF,       0
Unit.RequiresMountsFor,          config_parse_unit_requires_mounts_for, 0,                          0
Unit.StopWhenUnneeded,           config_parse_bool,                  0,                             offsetof(Unit, stop_when_unneeded)
Unit.RefuseManualStart,          config_parse_bool,                  0,                             offsetof(Unit, refuse_manual_start)
Unit.RefuseManualStop,           config_parse_bool,                  0,                             offsetof(Unit, refuse_manual_stop)
Unit.AllowIsolate,               config_parse_bool,                  0,                             offsetof(Unit, allow_isolate)
Unit.DefaultDependencies,        config_parse_bool,                  0,                             offsetof(Unit, default_dependencies)
Unit.OnFailureJobMode,           config_parse_job_mode,              0,                             offsetof(Unit, on_failure_job_mode)
Unit.OnFailureIsolate,           config_parse_job_mode_isolate,      0,                             offsetof(Unit, on_failure_job_mode)
Unit.IgnoreOnIsolate,            config_parse_bool,                  0,                             offsetof(Unit, ignore_on_isolate)
Unit.IgnoreOnSnapshot,           config_parse_bool,                  0,                             offsetof(Unit, ignore_on_snapshot)
Unit.JobTimeoutSec,              config_parse_sec,                   0,                             offsetof(Unit, job_timeout)
Unit.JobTimeoutAction,           config_parse_failure_action,        0,                             offsetof(Unit, job_timeout_action)
Unit.JobTimeoutRebootArgument,   config_parse_string,                0,                             offsetof(Unit, job_timeout_reboot_arg)
Unit.ConditionPathExists,        config_parse_unit_condition_path,   CONDITION_PATH_EXISTS,         offsetof(Unit, conditions)
Unit.ConditionPathExistsGlob,    config_parse_unit_condition_path,   CONDITION_PATH_EXISTS_GLOB,    offsetof(Unit, conditions)
Unit.ConditionPathIsDirectory,   config_parse_unit_condition_path,   CONDITION_PATH_IS_DIRECTORY,   offsetof(Unit, conditions)
Unit.ConditionPathIsSymbolicLink,config_parse_unit_condition_path,   CONDITION_PATH_IS_SYMBOLIC_LINK,offsetof(Unit, conditions)
Unit.ConditionPathIsMountPoint,  config_parse_unit_condition_path,   CONDITION_PATH_IS_MOUNT_POINT, offsetof(Unit, conditions)
Unit.ConditionPathIsReadWrite,   config_parse_unit_condition_path,   CONDITION_PATH_IS_READ_WRITE,  offsetof(Unit, conditions)
Unit.ConditionDirectoryNotEmpty, config_parse_unit_condition_path,   CONDITION_DIRECTORY_NOT_EMPTY, offsetof(Unit, conditions)
Unit.ConditionFileNotEmpty,      config_parse_unit_condition_path,   CONDITION_FILE_NOT_EMPTY,      offsetof(Unit, conditions)
Unit.ConditionFileIsExecutable,  config_parse_unit_condition_path,   CONDITION_FILE_IS_EXECUTABLE,  offsetof(Unit, conditions)
Unit.ConditionNeedsUpdate,       config_parse_unit_condition_path,   CONDITION_NEEDS_UPDATE,        offsetof(Unit, conditions)
Unit.ConditionFirstBoot,         config_parse_unit_condition_string, CONDITION_FIRST_BOOT,          offsetof(Unit, conditions)
Unit.ConditionKernelCommandLine, config_parse_unit_condition_string, CONDITION_KERNEL_COMMAND_LINE, offsetof(Unit, conditions)
Unit.ConditionArchitecture,      config_parse_unit_condition_string, CONDITION_ARCHITECTURE,        offsetof(Unit, conditions)
Unit.ConditionVirtualization,    config_parse_unit_condition_string, CONDITION_VIRTUALIZATION,      offsetof(Unit, conditions)
Unit.ConditionSecurity,          config_parse_unit_condition_string, CONDITION_SECURITY,            offsetof(Unit, conditions)
Unit.ConditionCapability,        config_parse_unit_condition_string, CONDITION_CAPABILITY,          offsetof(Unit, conditions)
Unit.ConditionHost,              config_parse_unit_condition_string, CONDITION_HOST,                offsetof(Unit, conditions)
Unit.ConditionACPower,           config_parse_unit_condition_string, CONDITION_AC_POWER,            offsetof(Unit, conditions)
Unit.ConditionNull,              config_parse_unit_condition_null,   0,                             offsetof(Unit, conditions)
Unit.AssertPathExists,           config_parse_unit_condition_path,   CONDITION_PATH_EXISTS,         offsetof(Unit, asserts)
Unit.AssertPathExistsGlob,       config_parse_unit_condition_path,   CONDITION_PATH_EXISTS_GLOB,    offsetof(Unit, asserts)
Unit.AssertPathIsDirectory,      config_parse_unit_condition_path,   CONDITION_PATH_IS_DIRECTORY,   offsetof(Unit, asserts)
Unit.AssertPathIsSymbolicLink,   config_parse_unit_condition_path,   CONDITION_PATH_IS_SYMBOLIC_LINK,offsetof(Unit, asserts)
Unit.AssertPathIsMountPoint,     config_parse_unit_condition_path,   CONDITION_PATH_IS_MOUNT_POINT, offsetof(Unit, asserts)
Unit.AssertPathIsReadWrite,      config_parse_unit_condition_path,   CONDITION_PATH_IS_READ_WRITE,  offsetof(Unit, asserts)
Unit.AssertDirectoryNotEmpty,    config_parse_unit_condition_path,   CONDITION_DIRECTORY_NOT_EMPTY, offsetof(Unit, asserts)
Unit.AssertFileNotEmpty,         config_parse_unit_condition_path,   CONDITION_FILE_NOT_EMPTY,      offsetof(Unit, asserts)
Unit.AssertFileIsExecutable,     config_parse_unit_condition_path,   CONDITION_FILE_IS_EXECUTABLE,  offsetof(Unit, asserts)
Unit.AssertNeedsUpdate,          config_parse_unit_condition_path,   CONDITION_NEEDS_UPDATE,        offsetof(Unit, asserts)
Unit.AssertFirstBoot,            config_parse_unit_condition_string, CONDITION_FIRST_BOOT,          offsetof(Unit, asserts)
Unit.AssertKernelCommandLine,    config_parse_unit_condition_string, CONDITION_KERNEL_COMMAND_LINE, offsetof(Unit, asserts)
Unit.AssertArchitecture,         config_parse_unit_condition_string, CONDITION_ARCHITECTURE,        offsetof(Unit, asserts)
Unit.AssertVirtualization,       config_parse_unit_condition_string, CONDITION_VIRTUALIZATION,      offsetof(Unit, asserts)
Unit.AssertSecurity,             config_parse_unit_condition_string, CONDITION_SECURITY,            offsetof(Unit, asserts)
Unit.AssertCapability,           config_parse_unit_condition_string, CONDITION_CAPABILITY,          offsetof(Unit, asserts)
Unit.AssertHost,                 config_parse_unit_condition_string, CONDITION_HOST,                offsetof(Unit, asserts)
Unit.AssertACPower,              config_parse_unit_condition_string, CONDITION_AC_POWER,            offsetof(Unit, asserts)
Unit.AssertNull,                 config_parse_unit_condition_null,   0,                             offsetof(Unit, asserts)
m4_dnl
Service.PIDFile,                 config_parse_unit_path_printf,      0,                             offsetof(Service, pid_file)
Service.ExecStartPre,            config_parse_exec,                  SERVICE_EXEC_START_PRE,        offsetof(Service, exec_command)
Service.ExecStart,               config_parse_exec,                  SERVICE_EXEC_START,            offsetof(Service, exec_command)
Service.ExecStartPost,           config_parse_exec,                  SERVICE_EXEC_START_POST,       offsetof(Service, exec_command)
Service.ExecReload,              config_parse_exec,                  SERVICE_EXEC_RELOAD,           offsetof(Service, exec_command)
Service.ExecStop,                config_parse_exec,                  SERVICE_EXEC_STOP,             offsetof(Service, exec_command)
Service.ExecStopPost,            config_parse_exec,                  SERVICE_EXEC_STOP_POST,        offsetof(Service, exec_command)
Service.RestartSec,              config_parse_sec,                   0,                             offsetof(Service, restart_usec)
Service.TimeoutSec,              config_parse_service_timeout,       0,                             offsetof(Service, timeout_start_usec)
Service.TimeoutStartSec,         config_parse_service_timeout,       0,                             offsetof(Service, timeout_start_usec)
Service.TimeoutStopSec,          config_parse_service_timeout,       0,                             offsetof(Service, timeout_stop_usec)
Service.WatchdogSec,             config_parse_sec,                   0,                             offsetof(Service, watchdog_usec)
Service.StartLimitInterval,      config_parse_sec,                   0,                             offsetof(Service, start_limit.interval)
Service.StartLimitBurst,         config_parse_unsigned,              0,                             offsetof(Service, start_limit.burst)
Service.StartLimitAction,        config_parse_failure_action,        0,                             offsetof(Service, start_limit_action)
Service.RebootArgument,          config_parse_string,                0,                             offsetof(Service, reboot_arg)
Service.FailureAction,           config_parse_failure_action,        0,                             offsetof(Service, failure_action)
Service.Type,                    config_parse_service_type,          0,                             offsetof(Service, type)
Service.Restart,                 config_parse_service_restart,       0,                             offsetof(Service, restart)
Service.PermissionsStartOnly,    config_parse_bool,                  0,                             offsetof(Service, permissions_start_only)
Service.RootDirectoryStartOnly,  config_parse_bool,                  0,                             offsetof(Service, root_directory_start_only)
Service.RemainAfterExit,         config_parse_bool,                  0,                             offsetof(Service, remain_after_exit)
Service.GuessMainPID,            config_parse_bool,                  0,                             offsetof(Service, guess_main_pid)
Service.RestartPreventExitStatus, config_parse_set_status,           0,                             offsetof(Service, restart_prevent_status)
Service.RestartForceExitStatus,  config_parse_set_status,            0,                             offsetof(Service, restart_force_status)
Service.SuccessExitStatus,       config_parse_set_status,            0,                             offsetof(Service, success_status)
Service.SysVStartPriority,       config_parse_warn_compat,           DISABLED_LEGACY,               0
Service.NonBlocking,             config_parse_bool,                  0,                             offsetof(Service, exec_context.non_blocking)
Service.BusName,                 config_parse_bus_name,              0,                             offsetof(Service, bus_name)
Service.FileDescriptorStoreMax,  config_parse_unsigned,              0,                             offsetof(Service, n_fd_store_max)
Service.NotifyAccess,            config_parse_notify_access,         0,                             offsetof(Service, notify_access)
Service.Sockets,                 config_parse_service_sockets,       0,                             0
Service.BusPolicy,               config_parse_bus_endpoint_policy,   0,                             offsetof(Service, exec_context)
EXEC_CONTEXT_CONFIG_ITEMS(Service)m4_dnl
CGROUP_CONTEXT_CONFIG_ITEMS(Service)m4_dnl
KILL_CONTEXT_CONFIG_ITEMS(Service)m4_dnl
m4_dnl
Socket.ListenStream,             config_parse_socket_listen,         SOCKET_SOCKET,                 0
Socket.ListenDatagram,           config_parse_socket_listen,         SOCKET_SOCKET,                 0
Socket.ListenSequentialPacket,   config_parse_socket_listen,         SOCKET_SOCKET,                 0
Socket.ListenFIFO,               config_parse_socket_listen,         SOCKET_FIFO,                   0
Socket.ListenNetlink,            config_parse_socket_listen,         SOCKET_SOCKET,                 0
Socket.ListenSpecial,            config_parse_socket_listen,         SOCKET_SPECIAL,                0
Socket.ListenMessageQueue,       config_parse_socket_listen,         SOCKET_MQUEUE,                 0
Socket.BindIPv6Only,             config_parse_socket_bind,           0,                             0,
Socket.Backlog,                  config_parse_unsigned,              0,                             offsetof(Socket, backlog)
Socket.BindToDevice,             config_parse_socket_bindtodevice,   0,                             0
Socket.ExecStartPre,             config_parse_exec,                  SOCKET_EXEC_START_PRE,         offsetof(Socket, exec_command)
Socket.ExecStartPost,            config_parse_exec,                  SOCKET_EXEC_START_POST,        offsetof(Socket, exec_command)
Socket.ExecStopPre,              config_parse_exec,                  SOCKET_EXEC_STOP_PRE,          offsetof(Socket, exec_command)
Socket.ExecStopPost,             config_parse_exec,                  SOCKET_EXEC_STOP_POST,         offsetof(Socket, exec_command)
Socket.TimeoutSec,               config_parse_sec,                   0,                             offsetof(Socket, timeout_usec)
Socket.SocketUser,               config_parse_unit_string_printf,    0,                             offsetof(Socket, user)
Socket.SocketGroup,              config_parse_unit_string_printf,    0,                             offsetof(Socket, group)
Socket.SocketMode,               config_parse_mode,                  0,                             offsetof(Socket, socket_mode)
Socket.DirectoryMode,            config_parse_mode,                  0,                             offsetof(Socket, directory_mode)
Socket.Accept,                   config_parse_bool,                  0,                             offsetof(Socket, accept)
Socket.MaxConnections,           config_parse_unsigned,              0,                             offsetof(Socket, max_connections)
Socket.KeepAlive,                config_parse_bool,                  0,                             offsetof(Socket, keep_alive)
Socket.KeepAliveTimeSec,         config_parse_sec,                   0,                             offsetof(Socket, keep_alive_time)
Socket.KeepAliveIntervalSec,     config_parse_sec,                   0,                             offsetof(Socket, keep_alive_interval)
Socket.KeepAliveProbes,          config_parse_unsigned,              0,                             offsetof(Socket, keep_alive_cnt)
Socket.DeferAcceptSec,           config_parse_sec,                   0,                             offsetof(Socket, defer_accept)
Socket.NoDelay,                  config_parse_bool,                  0,                             offsetof(Socket, no_delay)
Socket.Priority,                 config_parse_int,                   0,                             offsetof(Socket, priority)
Socket.ReceiveBuffer,            config_parse_iec_size,              0,                             offsetof(Socket, receive_buffer)
Socket.SendBuffer,               config_parse_iec_size,              0,                             offsetof(Socket, send_buffer)
Socket.IPTOS,                    config_parse_ip_tos,                0,                             offsetof(Socket, ip_tos)
Socket.IPTTL,                    config_parse_int,                   0,                             offsetof(Socket, ip_ttl)
Socket.Mark,                     config_parse_int,                   0,                             offsetof(Socket, mark)
Socket.PipeSize,                 config_parse_iec_size,              0,                             offsetof(Socket, pipe_size)
Socket.FreeBind,                 config_parse_bool,                  0,                             offsetof(Socket, free_bind)
Socket.Transparent,              config_parse_bool,                  0,                             offsetof(Socket, transparent)
Socket.Broadcast,                config_parse_bool,                  0,                             offsetof(Socket, broadcast)
Socket.PassCredentials,          config_parse_bool,                  0,                             offsetof(Socket, pass_cred)
Socket.PassSecurity,             config_parse_bool,                  0,                             offsetof(Socket, pass_sec)
Socket.TCPCongestion,            config_parse_string,                0,                             offsetof(Socket, tcp_congestion)
Socket.ReusePort,                config_parse_bool,                  0,                             offsetof(Socket, reuse_port)
Socket.MessageQueueMaxMessages,  config_parse_long,                  0,                             offsetof(Socket, mq_maxmsg)
Socket.MessageQueueMessageSize,  config_parse_long,                  0,                             offsetof(Socket, mq_msgsize)
Socket.RemoveOnStop,             config_parse_bool,                  0,                             offsetof(Socket, remove_on_stop)
Socket.Symlinks,                 config_parse_unit_path_strv_printf, 0,                             offsetof(Socket, symlinks)
Socket.Service,                  config_parse_socket_service,        0,                             0
m4_ifdef(`HAVE_SMACK',
`Socket.SmackLabel,              config_parse_string,                0,                             offsetof(Socket, smack)
Socket.SmackLabelIPIn,           config_parse_string,                0,                             offsetof(Socket, smack_ip_in)
Socket.SmackLabelIPOut,          config_parse_string,                0,                             offsetof(Socket, smack_ip_out)',
`Socket.SmackLabel,              config_parse_warn_compat,           DISABLED_CONFIGURATION,        0
Socket.SmackLabelIPIn,           config_parse_warn_compat,           DISABLED_CONFIGURATION,        0
Socket.SmackLabelIPOut,          config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')
m4_ifdef(`HAVE_SELINUX',
`Socket.SELinuxContextFromNet,   config_parse_bool,                  0,                             offsetof(Socket, selinux_context_from_net)',
`Socket.SELinuxContextFromNet,   config_parse_warn_compat,           DISABLED_CONFIGURATION,        0')
EXEC_CONTEXT_CONFIG_ITEMS(Socket)m4_dnl
CGROUP_CONTEXT_CONFIG_ITEMS(Socket)m4_dnl
KILL_CONTEXT_CONFIG_ITEMS(Socket)m4_dnl
m4_dnl
BusName.Name,                    config_parse_string,                0,                             offsetof(BusName, name)
BusName.Activating,              config_parse_bool,                  0,                             offsetof(BusName, activating)
BusName.Service,                 config_parse_busname_service,       0,                             0
BusName.AllowUser,               config_parse_bus_policy,            0,                             0
BusName.AllowGroup,              config_parse_bus_policy,            0,                             0
BusName.AllowWorld,              config_parse_bus_policy_world,      0,                             offsetof(BusName, policy_world)
BusName.SELinuxContext,          config_parse_exec_selinux_context,  0,                             0
BusName.AcceptFileDescriptors,   config_parse_bool,                  0,                             offsetof(BusName, accept_fd)
m4_dnl
Mount.What,                      config_parse_string,                0,                             offsetof(Mount, parameters_fragment.what)
Mount.Where,                     config_parse_path,                  0,                             offsetof(Mount, where)
Mount.Options,                   config_parse_string,                0,                             offsetof(Mount, parameters_fragment.options)
Mount.Type,                      config_parse_string,                0,                             offsetof(Mount, parameters_fragment.fstype)
Mount.TimeoutSec,                config_parse_sec,                   0,                             offsetof(Mount, timeout_usec)
Mount.DirectoryMode,             config_parse_mode,                  0,                             offsetof(Mount, directory_mode)
Mount.SloppyOptions,             config_parse_bool,                  0,                             offsetof(Mount, sloppy_options)
EXEC_CONTEXT_CONFIG_ITEMS(Mount)m4_dnl
CGROUP_CONTEXT_CONFIG_ITEMS(Mount)m4_dnl
KILL_CONTEXT_CONFIG_ITEMS(Mount)m4_dnl
m4_dnl
Automount.Where,                 config_parse_path,                  0,                             offsetof(Automount, where)
Automount.DirectoryMode,         config_parse_mode,                  0,                             offsetof(Automount, directory_mode)
Automount.TimeoutIdleSec,        config_parse_sec,                   0,                             offsetof(Automount, timeout_idle_usec)
m4_dnl
Swap.What,                       config_parse_path,                  0,                             offsetof(Swap, parameters_fragment.what)
Swap.Priority,                   config_parse_int,                   0,                             offsetof(Swap, parameters_fragment.priority)
Swap.Options,                    config_parse_string,                0,                             offsetof(Swap, parameters_fragment.options)
Swap.TimeoutSec,                 config_parse_sec,                   0,                             offsetof(Swap, timeout_usec)
EXEC_CONTEXT_CONFIG_ITEMS(Swap)m4_dnl
CGROUP_CONTEXT_CONFIG_ITEMS(Swap)m4_dnl
KILL_CONTEXT_CONFIG_ITEMS(Swap)m4_dnl
m4_dnl
Timer.OnCalendar,                config_parse_timer,                 0,                             0
Timer.OnActiveSec,               config_parse_timer,                 0,                             0
Timer.OnBootSec,                 config_parse_timer,                 0,                             0
Timer.OnStartupSec,              config_parse_timer,                 0,                             0
Timer.OnUnitActiveSec,           config_parse_timer,                 0,                             0
Timer.OnUnitInactiveSec,         config_parse_timer,                 0,                             0
Timer.Persistent,                config_parse_bool,                  0,                             offsetof(Timer, persistent)
Timer.WakeSystem,                config_parse_bool,                  0,                             offsetof(Timer, wake_system)
Timer.AccuracySec,               config_parse_sec,                   0,                             offsetof(Timer, accuracy_usec)
Timer.Unit,                      config_parse_trigger_unit,          0,                             0
m4_dnl
Path.PathExists,                 config_parse_path_spec,             0,                             0
Path.PathExistsGlob,             config_parse_path_spec,             0,                             0
Path.PathChanged,                config_parse_path_spec,             0,                             0
Path.PathModified,               config_parse_path_spec,             0,                             0
Path.DirectoryNotEmpty,          config_parse_path_spec,             0,                             0
Path.Unit,                       config_parse_trigger_unit,          0,                             0
Path.MakeDirectory,              config_parse_bool,                  0,                             offsetof(Path, make_directory)
Path.DirectoryMode,              config_parse_mode,                  0,                             offsetof(Path, directory_mode)
m4_dnl
CGROUP_CONTEXT_CONFIG_ITEMS(Slice)m4_dnl
m4_dnl
CGROUP_CONTEXT_CONFIG_ITEMS(Scope)m4_dnl
KILL_CONTEXT_CONFIG_ITEMS(Scope)m4_dnl
Scope.TimeoutStopSec,            config_parse_sec,                   0,                             offsetof(Scope, timeout_stop_usec)
m4_dnl The [Install] section is ignored here.
Install.Alias,                   NULL,                               0,                             0
Install.WantedBy,                NULL,                               0,                             0
Install.RequiredBy,              NULL,                               0,                             0
Install.Also,                    NULL,                               0,                             0
Install.DefaultInstance,         NULL,                               0,                             0
