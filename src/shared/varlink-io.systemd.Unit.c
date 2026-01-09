/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-idl-common.h"

/* CGroupContext */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupTasksMax,
                SD_VARLINK_FIELD_COMMENT("The maximum amount of tasks"),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The scaling factor"),
                SD_VARLINK_DEFINE_FIELD(scale, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupIODeviceWeight,
                SD_VARLINK_FIELD_COMMENT("The device path"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The device IO weight"),
                SD_VARLINK_DEFINE_FIELD(weight, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupIODeviceLimit,
                SD_VARLINK_FIELD_COMMENT("The device path"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The device IO limit"),
                SD_VARLINK_DEFINE_FIELD(limit, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupIODeviceLatency,
                SD_VARLINK_FIELD_COMMENT("The device path"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The device target latency"),
                SD_VARLINK_DEFINE_FIELD(targetUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupAddressPrefix,
                SD_VARLINK_FIELD_COMMENT("The address family"),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The address"),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The address prefix length"),
                SD_VARLINK_DEFINE_FIELD(prefixLength, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupSocketBind,
                SD_VARLINK_FIELD_COMMENT("The address family"),
                SD_VARLINK_DEFINE_FIELD(family, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The address protocol"),
                SD_VARLINK_DEFINE_FIELD(protocol, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The number of ports"),
                SD_VARLINK_DEFINE_FIELD(numberOfPorts, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The minimum port"),
                SD_VARLINK_DEFINE_FIELD(minimumPort, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupRestrictNetworkInterfaces,
                SD_VARLINK_FIELD_COMMENT("Whether this is an allow list"),
                SD_VARLINK_DEFINE_FIELD(isAllowList, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The list of interfaces"),
                SD_VARLINK_DEFINE_FIELD(interfaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupNFTSet,
                SD_VARLINK_FIELD_COMMENT("The source of this NFT set"),
                SD_VARLINK_DEFINE_FIELD(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The NFT protocol for this NFT set"),
                SD_VARLINK_DEFINE_FIELD(protocol, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The NFT table associated with this NFT set"),
                SD_VARLINK_DEFINE_FIELD(table, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The name of the NFT set"),
                SD_VARLINK_DEFINE_FIELD(set, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupBPFProgram,
                SD_VARLINK_FIELD_COMMENT("The BPF program attach type"),
                SD_VARLINK_DEFINE_FIELD(attachType, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The path to the BPF program"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupDeviceAllow,
                SD_VARLINK_FIELD_COMMENT("The device path"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The device permissions"),
                SD_VARLINK_DEFINE_FIELD(permissions, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupContext,

                SD_VARLINK_FIELD_COMMENT("Slice of the CGroup"),
                SD_VARLINK_DEFINE_FIELD(Slice, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                /* CPU Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#CPU%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#CPUWeight=weight"),
                SD_VARLINK_DEFINE_FIELD(CPUWeight, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#CPUWeight=weight"),
                SD_VARLINK_DEFINE_FIELD(StartupCPUWeight, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#CPUQuota="),
                SD_VARLINK_DEFINE_FIELD(CPUQuotaPerSecUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#CPUQuotaPeriodSec="),
                SD_VARLINK_DEFINE_FIELD(CPUQuotaPeriodUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#AllowedCPUs="),
                SD_VARLINK_DEFINE_FIELD(AllowedCPUs, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#AllowedCPUs="),
                SD_VARLINK_DEFINE_FIELD(StartupAllowedCPUs, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Memory Accounting and Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Memory%20Accounting%20and%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryAccounting="),
                SD_VARLINK_DEFINE_FIELD(MemoryAccounting, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryMin=bytes,%20MemoryLow=bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryMin, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryMin=bytes,%20MemoryLow=bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryLow, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryMin=bytes,%20MemoryLow=bytes"),
                SD_VARLINK_DEFINE_FIELD(StartupMemoryLow, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryHigh=bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryHigh, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryHigh=bytes"),
                SD_VARLINK_DEFINE_FIELD(StartupMemoryHigh, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryMax=bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryMax=bytes"),
                SD_VARLINK_DEFINE_FIELD(StartupMemoryMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemorySwapMax=bytes"),
                SD_VARLINK_DEFINE_FIELD(MemorySwapMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemorySwapMax=bytes"),
                SD_VARLINK_DEFINE_FIELD(StartupMemorySwapMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryZSwapMax=bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryZSwapMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryZSwapMax=bytes"),
                SD_VARLINK_DEFINE_FIELD(StartupMemoryZSwapMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryZSwapWriteback="),
                SD_VARLINK_DEFINE_FIELD(MemoryZSwapWriteback, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#AllowedMemoryNodes="),
                SD_VARLINK_DEFINE_FIELD(AllowedMemoryNodes, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#AllowedMemoryNodes="),
                SD_VARLINK_DEFINE_FIELD(StartupAllowedMemoryNodes, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Process Accounting and Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Process%20Accounting%20and%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#TasksAccounting="),
                SD_VARLINK_DEFINE_FIELD(TasksAccounting, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#TasksMax=N"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(TasksMax, CGroupTasksMax, SD_VARLINK_NULLABLE),

                /* IO Accounting and Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#IO%20Accounting%20and%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOAccounting="),
                SD_VARLINK_DEFINE_FIELD(IOAccounting, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOWeight=weight"),
                SD_VARLINK_DEFINE_FIELD(IOWeight, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOWeight=weight"),
                SD_VARLINK_DEFINE_FIELD(StartupIOWeight, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IODeviceWeight=device%20weight"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IODeviceWeight, CGroupIODeviceWeight, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOReadBandwidthMax=device%20bytes"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IOReadBandwidthMax, CGroupIODeviceLimit, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOReadBandwidthMax=device%20bytes"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IOWriteBandwidthMax, CGroupIODeviceLimit, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOReadIOPSMax=device%20IOPS"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IOReadIOPSMax, CGroupIODeviceLimit, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOReadIOPSMax=device%20IOPS"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IOWriteIOPSMax, CGroupIODeviceLimit, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IODeviceLatencyTargetSec=device%20target"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IODeviceLatencyTargetUSec, CGroupIODeviceLatency, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Network Accounting and Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Network%20Accounting%20and%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IPAccounting="),
                SD_VARLINK_DEFINE_FIELD(IPAccounting, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IPAddressAllow=ADDRESS%5B/PREFIXLENGTH%5D%E2%80%A6"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IPAddressAllow, CGroupAddressPrefix, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IPAddressAllow=ADDRESS%5B/PREFIXLENGTH%5D%E2%80%A6"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IPAddressDeny, CGroupAddressPrefix, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#SocketBindAllow=bind-rule"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SocketBindAllow, CGroupSocketBind, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#SocketBindAllow=bind-rule"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SocketBindDeny, CGroupSocketBind, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#RestrictNetworkInterfaces="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RestrictNetworkInterfaces, CGroupRestrictNetworkInterfaces, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#NFTSet=family:table:set"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(NFTSet, CGroupNFTSet, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* BPF programs
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#BPF%20Programs */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IPIngressFilterPath=BPF_FS_PROGRAM_PATH"),
                SD_VARLINK_DEFINE_FIELD(IPIngressFilterPath, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IPIngressFilterPath=BPF_FS_PROGRAM_PATH"),
                SD_VARLINK_DEFINE_FIELD(IPEgressFilterPath, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#BPFProgram=type:program-path"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(BPFProgram, CGroupBPFProgram, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Device Access
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Device%20Access */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DeviceAllow="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(DeviceAllow, CGroupDeviceAllow, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DevicePolicy=auto%7Cclosed%7Cstrict"),
                SD_VARLINK_DEFINE_FIELD(DevicePolicy, SD_VARLINK_STRING, 0),

                /* Control Group Management
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Control%20Group%20Management */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#Delegate="),
                SD_VARLINK_DEFINE_FIELD(Delegate, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DelegateSubgroup="),
                SD_VARLINK_DEFINE_FIELD(DelegateSubgroup, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DisableControllers="),
                SD_VARLINK_DEFINE_FIELD(DelegateControllers, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DisableControllers="),
                SD_VARLINK_DEFINE_FIELD(DisableControllers, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Memory Pressure Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Memory%20Pressure%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMSwap=auto%7Ckill"),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMSwap, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMSwap=auto%7Ckill"),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMMemoryPressure, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMMemoryPressureLimit="),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMMemoryPressureLimit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMMemoryPressureDurationSec="),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMMemoryPressureDurationUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMPreference=none%7Cavoid%7Comit"),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMPreference, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryPressureWatch="),
                SD_VARLINK_DEFINE_FIELD(MemoryPressureWatch, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryPressureThresholdSec="),
                SD_VARLINK_DEFINE_FIELD(MemoryPressureThresholdUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),

                /* Others */
                SD_VARLINK_FIELD_COMMENT("Reflects whether to forward coredumps for processes that crash within this cgroup"),
                SD_VARLINK_DEFINE_FIELD(CoredumpReceive, SD_VARLINK_BOOL, 0));

/* ExecContext */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                WorkingDirectory,
                SD_VARLINK_FIELD_COMMENT("The path to the working directory"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the path to the working directory is allowed to not exist"),
                SD_VARLINK_DEFINE_FIELD(missingOK, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PartitionMountOptions,
                SD_VARLINK_FIELD_COMMENT("The partition designator to which the options apply"),
                SD_VARLINK_DEFINE_FIELD(partitionDesignator, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The mount options for this partition"),
                SD_VARLINK_DEFINE_FIELD(options, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                BindPath,
                SD_VARLINK_FIELD_COMMENT("The mount source path"),
                SD_VARLINK_DEFINE_FIELD(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The mount destination path"),
                SD_VARLINK_DEFINE_FIELD(destination, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether a missing source path should be ignored"),
                SD_VARLINK_DEFINE_FIELD(ignoreEnoent, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Mount options"),
                SD_VARLINK_DEFINE_FIELD(options, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                MountImage,
                SD_VARLINK_FIELD_COMMENT("The path to the image to mount"),
                SD_VARLINK_DEFINE_FIELD(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The destination path where to mount the image"),
                SD_VARLINK_DEFINE_FIELD(destination, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether failure to find the image is considered fatal"),
                SD_VARLINK_DEFINE_FIELD(ignoreEnoent, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The mount options to use for the partitions of the image"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(mountOptions, PartitionMountOptions, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ExtensionImage,
                SD_VARLINK_FIELD_COMMENT("The path to the extension image"),
                SD_VARLINK_DEFINE_FIELD(source, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether failure to find the extension image is considered fatal"),
                SD_VARLINK_DEFINE_FIELD(ignoreEnoent, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The mount options to use for the partitions of the extension image"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(mountOptions, PartitionMountOptions, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SELinuxContext,
                SD_VARLINK_FIELD_COMMENT("Whether failure to set the SELinux context is ignored"),
                SD_VARLINK_DEFINE_FIELD(ignore, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The SELinux context"),
                SD_VARLINK_DEFINE_FIELD(context, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                AppArmorProfile,
                SD_VARLINK_FIELD_COMMENT("Whether failure to configure the apparmor profile will be ignored"),
                SD_VARLINK_DEFINE_FIELD(ignore, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The AppArmor profile"),
                SD_VARLINK_DEFINE_FIELD(profile, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SmackProcessLabel,
                SD_VARLINK_FIELD_COMMENT("Whether failure to configure the smack process label will be ignored"),
                SD_VARLINK_DEFINE_FIELD(ignore, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The smack process label"),
                SD_VARLINK_DEFINE_FIELD(label, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CPUAffinity,
                SD_VARLINK_FIELD_COMMENT("CPU affinity of the executed processes"),
                SD_VARLINK_DEFINE_FIELD(affinity, SD_VARLINK_INT, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("CPU affinity from NUMA"),
                SD_VARLINK_DEFINE_FIELD(fromNUMA, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ExecDirectoryQuota,
                SD_VARLINK_FIELD_COMMENT("Whether the quota is accounted"),
                SD_VARLINK_DEFINE_FIELD(accounting, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the quota is enforced"),
                SD_VARLINK_DEFINE_FIELD(enforce, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The absolute quota in bytes"),
                SD_VARLINK_DEFINE_FIELD(quotaAbsolute, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The scaling factor for the quota"),
                SD_VARLINK_DEFINE_FIELD(quotaScale, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ExecDirectoryPath,
                SD_VARLINK_FIELD_COMMENT("The path to the directory"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A list of symlinks pointing to the directory"),
                SD_VARLINK_DEFINE_FIELD(symlinks, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ExecDirectory,
                SD_VARLINK_FIELD_COMMENT("Exec directory paths"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(paths, ExecDirectoryPath, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The access mode of the directory"),
                SD_VARLINK_DEFINE_FIELD(mode, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The quota for the directory"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(quota, ExecDirectoryQuota, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TemporaryFilesystem,
                SD_VARLINK_FIELD_COMMENT("The destination path where the temporary filesystem should be mounted"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The mount options for the temporary filesystem"),
                SD_VARLINK_DEFINE_FIELD(options, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                AddressFamilyList,
                SD_VARLINK_FIELD_COMMENT("Whether the list of address families is an allow list"),
                SD_VARLINK_DEFINE_FIELD(isAllowList, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The list of address families"),
                SD_VARLINK_DEFINE_FIELD(addressFamilies, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                FilesystemList,
                SD_VARLINK_FIELD_COMMENT("Whether the list of filesystems is an allow list"),
                SD_VARLINK_DEFINE_FIELD(isAllowList, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The list of filesystems"),
                SD_VARLINK_DEFINE_FIELD(filesystems, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SystemCallList,
                SD_VARLINK_FIELD_COMMENT("Whether the list of system calls is an allow list"),
                SD_VARLINK_DEFINE_FIELD(isAllowList, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The list of system calls"),
                SD_VARLINK_DEFINE_FIELD(systemCalls, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                EnvironmentFile,
                SD_VARLINK_FIELD_COMMENT("The path to the environment file"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether failure to read the environment file is fatal or not"),
                SD_VARLINK_DEFINE_FIELD(graceful, SD_VARLINK_BOOL, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                LogFilterPattern,
                SD_VARLINK_FIELD_COMMENT("Whether this pattern is an allow pattern"),
                SD_VARLINK_DEFINE_FIELD(isAllowList, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The filtering pattern"),
                SD_VARLINK_DEFINE_FIELD(pattern, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                LoadCredential,
                SD_VARLINK_FIELD_COMMENT("The credential ID"),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The credential path"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ImportCredential,
                SD_VARLINK_FIELD_COMMENT("The glob pattern to find credentials"),
                SD_VARLINK_DEFINE_FIELD(glob, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The rename pattern to which matching credentials should be renamed"),
                SD_VARLINK_DEFINE_FIELD(rename, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SetCredential,
                SD_VARLINK_FIELD_COMMENT("The credential ID"),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The credential value encoded in base64"),
                SD_VARLINK_DEFINE_FIELD(value, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ExecContext,

                /* Paths
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Paths */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ExecSearchPath="),
                SD_VARLINK_DEFINE_FIELD(ExecSearchPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#WorkingDirectory="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(WorkingDirectory, WorkingDirectory, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootDirectory="),
                SD_VARLINK_DEFINE_FIELD(RootDirectory, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootImage="),
                SD_VARLINK_DEFINE_FIELD(RootImage, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootImageOptions="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RootImageOptions, PartitionMountOptions, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootEphemeral="),
                SD_VARLINK_DEFINE_FIELD(RootEphemeral, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootHash="),
                SD_VARLINK_DEFINE_FIELD(RootHash, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootHash="),
                SD_VARLINK_DEFINE_FIELD(RootHashPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootHashSignature="),
                SD_VARLINK_DEFINE_FIELD(RootHashSignature, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootHashSignature="),
                SD_VARLINK_DEFINE_FIELD(RootHashSignaturePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootVerity="),
                SD_VARLINK_DEFINE_FIELD(RootVerity, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootImagePolicy="),
                SD_VARLINK_DEFINE_FIELD(RootImagePolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootImagePolicy="),
                SD_VARLINK_DEFINE_FIELD(MountImagePolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootImagePolicy="),
                SD_VARLINK_DEFINE_FIELD(ExtensionImagePolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MountAPIVFS="),
                SD_VARLINK_DEFINE_FIELD(MountAPIVFS, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BindLogSockets="),
                SD_VARLINK_DEFINE_FIELD(BindLogSockets, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectProc="),
                SD_VARLINK_DEFINE_FIELD(ProtectProc, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProcSubset="),
                SD_VARLINK_DEFINE_FIELD(ProcSubset, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BindPaths="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(BindPaths, BindPath, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BindPaths="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(BindReadOnlyPaths, BindPath, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MountImages="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(MountImages, MountImage, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ExtensionImages="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExtensionImages, ExtensionImage, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ExtensionDirectories="),
                SD_VARLINK_DEFINE_FIELD(ExtensionDirectories, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* User/Group Identity
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#User/Group%20Identity */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#User="),
                SD_VARLINK_DEFINE_FIELD(User, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#User="),
                SD_VARLINK_DEFINE_FIELD(Group, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#DynamicUser="),
                SD_VARLINK_DEFINE_FIELD(DynamicUser, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SupplementaryGroups="),
                SD_VARLINK_DEFINE_FIELD(SupplementaryGroups, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SetLoginEnvironment="),
                SD_VARLINK_DEFINE_FIELD(SetLoginEnvironment, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PAMName="),
                SD_VARLINK_DEFINE_FIELD(PAMName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                /* Capabilities
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Capabilities */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CapabilityBoundingSet="),
                SD_VARLINK_DEFINE_FIELD(CapabilityBoundingSet, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#AmbientCapabilities="),
                SD_VARLINK_DEFINE_FIELD(AmbientCapabilities, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Security
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Security */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#NoNewPrivileges="),
                SD_VARLINK_DEFINE_FIELD(NoNewPrivileges, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SecureBits="),
                SD_VARLINK_DEFINE_FIELD(SecureBits, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Mandatory Access Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Mandatory%20Access%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SELinuxContext="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SELinuxContext, SELinuxContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#AppArmorProfile="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(AppArmorProfile, AppArmorProfile, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SmackProcessLabel="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SmackProcessLabel, SmackProcessLabel, SD_VARLINK_NULLABLE),

                /* Process Properties
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Process%20Properties */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LimitCPU="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Limits, ResourceLimitTable, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#UMask="),
                SD_VARLINK_DEFINE_FIELD(UMask, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CoredumpFilter="),
                SD_VARLINK_DEFINE_FIELD(CoredumpFilter, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#KeyringMode="),
                SD_VARLINK_DEFINE_FIELD(KeyringMode, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#OOMScoreAdjust="),
                SD_VARLINK_DEFINE_FIELD(OOMScoreAdjust, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TimerSlackNSec="),
                SD_VARLINK_DEFINE_FIELD(TimerSlackNSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#Personality="),
                SD_VARLINK_DEFINE_FIELD(Personality, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#IgnoreSIGPIPE="),
                SD_VARLINK_DEFINE_FIELD(IgnoreSIGPIPE, SD_VARLINK_BOOL, 0),

                /* Scheduling
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Scheduling */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#Nice="),
                SD_VARLINK_DEFINE_FIELD(Nice, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUSchedulingPolicy="),
                SD_VARLINK_DEFINE_FIELD(CPUSchedulingPolicy, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUSchedulingPriority="),
                SD_VARLINK_DEFINE_FIELD(CPUSchedulingPriority, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUSchedulingResetOnFork="),
                SD_VARLINK_DEFINE_FIELD(CPUSchedulingResetOnFork, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUAffinity="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CPUAffinity, CPUAffinity, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#NUMAPolicy="),
                SD_VARLINK_DEFINE_FIELD(NUMAPolicy, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#NUMAMask="),
                SD_VARLINK_DEFINE_FIELD(NUMAMask, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#IOSchedulingClass="),
                SD_VARLINK_DEFINE_FIELD(IOSchedulingClass, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#IOSchedulingPriority="),
                SD_VARLINK_DEFINE_FIELD(IOSchedulingPriority, SD_VARLINK_INT, 0),

                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MemoryKSM="),
                SD_VARLINK_DEFINE_FIELD(MemoryKSM, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MemoryTHP="),
                SD_VARLINK_DEFINE_FIELD(MemoryTHP, SD_VARLINK_STRING, 0),

                /* Sandboxing
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Sandboxing */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectSystem="),
                SD_VARLINK_DEFINE_FIELD(ProtectSystem, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectHome="),
                SD_VARLINK_DEFINE_FIELD(ProtectHome, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RuntimeDirectory="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RuntimeDirectory, ExecDirectory, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RuntimeDirectory="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StateDirectory, ExecDirectory, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RuntimeDirectory="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CacheDirectory, ExecDirectory, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RuntimeDirectory="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LogsDirectory, ExecDirectory, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RuntimeDirectory="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ConfigurationDirectory, ExecDirectory, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RuntimeDirectoryPreserve="),
                SD_VARLINK_DEFINE_FIELD(RuntimeDirectoryPreserve, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TimeoutCleanSec="),
                SD_VARLINK_DEFINE_FIELD(TimeoutCleanUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ReadWritePaths="),
                SD_VARLINK_DEFINE_FIELD(ReadWritePaths, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ReadWritePaths="),
                SD_VARLINK_DEFINE_FIELD(ReadOnlyPaths, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ReadWritePaths="),
                SD_VARLINK_DEFINE_FIELD(InaccessiblePaths, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ReadWritePaths="),
                SD_VARLINK_DEFINE_FIELD(ExecPaths, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ReadWritePaths="),
                SD_VARLINK_DEFINE_FIELD(NoExecPaths, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TemporaryFileSystem="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(TemporaryFileSystem, TemporaryFilesystem, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateTmp="),
                SD_VARLINK_DEFINE_FIELD(PrivateTmp, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateDevices="),
                SD_VARLINK_DEFINE_FIELD(PrivateDevices, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateNetwork="),
                SD_VARLINK_DEFINE_FIELD(PrivateNetwork, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#NetworkNamespacePath="),
                SD_VARLINK_DEFINE_FIELD(NetworkNamespacePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateIPC="),
                SD_VARLINK_DEFINE_FIELD(PrivateIPC, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#IPCNamespacePath="),
                SD_VARLINK_DEFINE_FIELD(IPCNamespacePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivatePIDs="),
                SD_VARLINK_DEFINE_FIELD(PrivatePIDs, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateUsers="),
                SD_VARLINK_DEFINE_FIELD(PrivateUsers, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#UserNamespacePath="),
                SD_VARLINK_DEFINE_FIELD(UserNamespacePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectHostname="),
                SD_VARLINK_DEFINE_FIELD(ProtectHostname, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectClock="),
                SD_VARLINK_DEFINE_FIELD(ProtectClock, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectKernelTunables="),
                SD_VARLINK_DEFINE_FIELD(ProtectKernelTunables, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectKernelModules="),
                SD_VARLINK_DEFINE_FIELD(ProtectKernelModules, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectKernelLogs="),
                SD_VARLINK_DEFINE_FIELD(ProtectKernelLogs, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectControlGroups="),
                SD_VARLINK_DEFINE_FIELD(ProtectControlGroups, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictAddressFamilies="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RestrictAddressFamilies, AddressFamilyList, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictFileSystems="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RestrictFilesystems, FilesystemList, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictNamespaces="),
                SD_VARLINK_DEFINE_FIELD(RestrictNamespaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#DelegateNamespaces="),
                SD_VARLINK_DEFINE_FIELD(DelegateNamespaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivatePBF="),
                SD_VARLINK_DEFINE_FIELD(PrivatePBF, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BPFDelegateCommands="),
                SD_VARLINK_DEFINE_FIELD(BPFDelegateCommands, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BPFDelegateMaps="),
                SD_VARLINK_DEFINE_FIELD(BPFDelegateMaps, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BPFDelegatePrograms="),
                SD_VARLINK_DEFINE_FIELD(BPFDelegatePrograms, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#BPFDelegateAttachments="),
                SD_VARLINK_DEFINE_FIELD(BPFDelegateAttachments, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LockPersonality="),
                SD_VARLINK_DEFINE_FIELD(LockPersonality, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MemoryDenyWriteExecute="),
                SD_VARLINK_DEFINE_FIELD(MemoryDenyWriteExecute, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictRealtime="),
                SD_VARLINK_DEFINE_FIELD(RestrictRealtime, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictSUIDSGID="),
                SD_VARLINK_DEFINE_FIELD(RestrictSUIDSGID, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether to remove all System V and POSIX IPC objects owned by the user and group this unit runs under"),
                SD_VARLINK_DEFINE_FIELD(RemoveIPC, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateMounts="),
                SD_VARLINK_DEFINE_FIELD(PrivateMounts, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MountFlags="),
                SD_VARLINK_DEFINE_FIELD(MountFlags, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                /* System Call Filtering
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#System%20Call%20Filtering */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SystemCallFilter="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SystemCallFilter, SystemCallList, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SystemCallErrorNumber="),
                SD_VARLINK_DEFINE_FIELD(SystemCallErrorNumber, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SystemCallArchitectures="),
                SD_VARLINK_DEFINE_FIELD(SystemCallArchitectures, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SystemCallLog="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SystemCallLog, SystemCallList, SD_VARLINK_NULLABLE),

                /* Environment
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Environment */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#Environment="),
                SD_VARLINK_DEFINE_FIELD(Environment, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#EnvironmentFile="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(EnvironmentFiles, EnvironmentFile, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PassEnvironment="),
                SD_VARLINK_DEFINE_FIELD(PassEnvironment, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#UnsetEnvironment="),
                SD_VARLINK_DEFINE_FIELD(UnsetEnvironment, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Logging and Standard Input/Output
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Logging%20and%20Standard%20Input/Output */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#StandardInput="),
                SD_VARLINK_DEFINE_FIELD(StandardInput, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#StandardOutput="),
                SD_VARLINK_DEFINE_FIELD(StandardOutput, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#StandardError="),
                SD_VARLINK_DEFINE_FIELD(StandardError, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The file descriptor name to connect standard input to"),
                SD_VARLINK_DEFINE_FIELD(StandardInputFileDescriptorName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The file descriptor name to connect standard output to"),
                SD_VARLINK_DEFINE_FIELD(StandardOutputFileDescriptorName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The file descriptor name to connect standard error to"),
                SD_VARLINK_DEFINE_FIELD(StandardErrorFileDescriptorName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#StandardInputText="),
                SD_VARLINK_DEFINE_FIELD(StandardInputData, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LogLevelMax="),
                SD_VARLINK_DEFINE_FIELD(LogLevelMax, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LogExtraFields="),
                SD_VARLINK_DEFINE_FIELD(LogExtraFields, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LogRateLimitIntervalSec="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LogRateLimit, RateLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LogFilterPatterns="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LogFilterPatterns, LogFilterPattern, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LogNamespace="),
                SD_VARLINK_DEFINE_FIELD(LogNamespace, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SyslogIdentifier="),
                SD_VARLINK_DEFINE_FIELD(SyslogIdentifier, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SyslogFacility="),
                SD_VARLINK_DEFINE_FIELD(SyslogFacility, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SyslogLevel="),
                SD_VARLINK_DEFINE_FIELD(SyslogLevel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SyslogLevelPrefix="),
                SD_VARLINK_DEFINE_FIELD(SyslogLevelPrefix, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TTYPath="),
                SD_VARLINK_DEFINE_FIELD(TTYPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TTYReset="),
                SD_VARLINK_DEFINE_FIELD(TTYReset, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TTYVHangup="),
                SD_VARLINK_DEFINE_FIELD(TTYVHangup, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TTYRows="),
                SD_VARLINK_DEFINE_FIELD(TTYRows, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TTYRows="),
                SD_VARLINK_DEFINE_FIELD(TTYColumns, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#TTYVTDisallocate="),
                SD_VARLINK_DEFINE_FIELD(TTYVTDisallocate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),

                /* Credentials
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Credentials */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LoadCredential=ID:PATH"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LoadCredential, LoadCredential, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#LoadCredential=ID:PATH"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LoadCredentialEncrypted, LoadCredential, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ImportCredential=GLOB"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ImportCredential, ImportCredential, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SetCredential=ID:VALUE"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SetCredential, SetCredential, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#SetCredential=ID:VALUE"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SetCredentialEncrypted, SetCredential, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* System V Compatibility
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#System%20V%20Compatibility */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#UtmpIdentifier="),
                SD_VARLINK_DEFINE_FIELD(UtmpIdentifier, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#UtmpMode="),
                SD_VARLINK_DEFINE_FIELD(UtmpMode, SD_VARLINK_STRING, 0));

/* UnitContext */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Condition,
                SD_VARLINK_FIELD_COMMENT("The condition type"),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the condition is a triggering condition"),
                SD_VARLINK_DEFINE_FIELD(trigger, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the result of the condition is negated"),
                SD_VARLINK_DEFINE_FIELD(negate, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The parameter passed to the condition"),
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                UnitContext,
                SD_VARLINK_FIELD_COMMENT("The unit type"),
                SD_VARLINK_DEFINE_FIELD(Type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The unit ID"),
                SD_VARLINK_DEFINE_FIELD(ID, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The aliases of this unit"),
                SD_VARLINK_DEFINE_FIELD(Names, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* [Unit] Section Options
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#%5BUnit%5D%20Section%20Options */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Description="),
                SD_VARLINK_DEFINE_FIELD(Description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Documentation="),
                SD_VARLINK_DEFINE_FIELD(Documentation, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Wants="),
                SD_VARLINK_DEFINE_FIELD(Wants, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#WantedBy="),
                SD_VARLINK_DEFINE_FIELD(WantedBy, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Requires="),
                SD_VARLINK_DEFINE_FIELD(Requires, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#WantedBy="),
                SD_VARLINK_DEFINE_FIELD(RequiredBy, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Requisite="),
                SD_VARLINK_DEFINE_FIELD(Requisite, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Requisite="),
                SD_VARLINK_DEFINE_FIELD(RequisiteOf, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#BindsTo="),
                SD_VARLINK_DEFINE_FIELD(BindsTo, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#BindsTo="),
                SD_VARLINK_DEFINE_FIELD(BoundBy, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#PartOf="),
                SD_VARLINK_DEFINE_FIELD(PartOf, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#PartOf="),
                SD_VARLINK_DEFINE_FIELD(ConsistsOf, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Upholds="),
                SD_VARLINK_DEFINE_FIELD(Upholds, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#WantedBy="),
                SD_VARLINK_DEFINE_FIELD(UpheldBy, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Conflicts="),
                SD_VARLINK_DEFINE_FIELD(Conflicts, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The ConflictedBy= dependencies of this unit"),
                SD_VARLINK_DEFINE_FIELD(ConflictedBy, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Before="),
                SD_VARLINK_DEFINE_FIELD(Before, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#Before="),
                SD_VARLINK_DEFINE_FIELD(After, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#OnFailure="),
                SD_VARLINK_DEFINE_FIELD(OnFailure, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The OnFailureOf= dependencies of this unit"),
                SD_VARLINK_DEFINE_FIELD(OnFailureOf, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#OnSuccess="),
                SD_VARLINK_DEFINE_FIELD(OnSuccess, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The OnSuccessOf= dependencies of this unit"),
                SD_VARLINK_DEFINE_FIELD(OnSuccessOf, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#PropagatesReloadTo="),
                SD_VARLINK_DEFINE_FIELD(PropagatesReloadTo, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#PropagatesReloadTo="),
                SD_VARLINK_DEFINE_FIELD(ReloadPropagatedFrom, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#PropagatesStopTo="),
                SD_VARLINK_DEFINE_FIELD(PropagatesStopTo, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#PropagatesStopTo="),
                SD_VARLINK_DEFINE_FIELD(StopPropagatedFrom, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JoinsNamespaceOf="),
                SD_VARLINK_DEFINE_FIELD(JoinsNamespaceOf, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#RequiresMountsFor="),
                SD_VARLINK_DEFINE_FIELD(RequiresMountsFor, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#WantsMountsFor="),
                SD_VARLINK_DEFINE_FIELD(WantsMountsFor, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#OnSuccessJobMode="),
                SD_VARLINK_DEFINE_FIELD(OnSuccessJobMode, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#OnSuccessJobMode="),
                SD_VARLINK_DEFINE_FIELD(OnFailureJobMode, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#IgnoreOnIsolate="),
                SD_VARLINK_DEFINE_FIELD(IgnoreOnIsolate, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#StopWhenUnneeded="),
                SD_VARLINK_DEFINE_FIELD(StopWhenUnneeded, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#RefuseManualStart="),
                SD_VARLINK_DEFINE_FIELD(RefuseManualStart, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#RefuseManualStart="),
                SD_VARLINK_DEFINE_FIELD(RefuseManualStop, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#AllowIsolate="),
                SD_VARLINK_DEFINE_FIELD(AllowIsolate, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#DefaultDependencies="),
                SD_VARLINK_DEFINE_FIELD(DefaultDependencies, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#SurviveFinalKillSignal="),
                SD_VARLINK_DEFINE_FIELD(SurviveFinalKillSignal, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#CollectMode="),
                SD_VARLINK_DEFINE_FIELD(CollectMode, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureAction="),
                SD_VARLINK_DEFINE_FIELD(FailureAction, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureAction="),
                SD_VARLINK_DEFINE_FIELD(SuccessAction, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureActionExitStatus="),
                SD_VARLINK_DEFINE_FIELD(FailureActionExitStatus, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureActionExitStatus="),
                SD_VARLINK_DEFINE_FIELD(SuccessActionExitStatus, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(JobTimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(JobRunningTimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutAction="),
                SD_VARLINK_DEFINE_FIELD(JobTimeoutAction, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutAction="),
                SD_VARLINK_DEFINE_FIELD(JobTimeoutRebootArgument, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#StartLimitIntervalSec=interval"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StartLimit, RateLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#StartLimitIntervalSec=interval"),
                SD_VARLINK_DEFINE_FIELD(StartLimitAction, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#RebootArgument="),
                SD_VARLINK_DEFINE_FIELD(RebootArgument, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#SourcePath="),
                SD_VARLINK_DEFINE_FIELD(SourcePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                /* Conditions and Asserts
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.unit.html#Conditions%20and%20Asserts */
                SD_VARLINK_FIELD_COMMENT("The conditions of this unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Conditions, Condition, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The asserts of this unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Asserts, Condition, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Others */
                SD_VARLINK_FIELD_COMMENT("The Triggers= dependencies of this unit"),
                SD_VARLINK_DEFINE_FIELD(Triggers, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The TriggeredBy= dependencies of this unit"),
                SD_VARLINK_DEFINE_FIELD(TriggeredBy, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The SELinux context that is used to control access to the unit"),
                SD_VARLINK_DEFINE_FIELD(AccessSELinuxContext, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The unit file path this unit was read from"),
                SD_VARLINK_DEFINE_FIELD(FragmentPath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The paths from which drop-in files were read for this unit"),
                SD_VARLINK_DEFINE_FIELD(DropInPaths, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The unit file preset for this unit"),
                SD_VARLINK_DEFINE_FIELD(UnitFilePreset, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether this unit is transient"),
                SD_VARLINK_DEFINE_FIELD(Transient, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether this unit is perpetual"),
                SD_VARLINK_DEFINE_FIELD(Perpetual, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("When true, logs about this unit will be at debug level regardless of other log level settings"),
                SD_VARLINK_DEFINE_FIELD(DebugInvocation, SD_VARLINK_BOOL, 0),

                /* Other contexts */
                SD_VARLINK_FIELD_COMMENT("The cgroup context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CGroup, CGroupContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The exec context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Exec, ExecContext, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ActivationDetails,
                SD_VARLINK_FIELD_COMMENT("Trigger unit type"),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Trigger unit name"),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                CGroupRuntime,

                /* ID */
                SD_VARLINK_FIELD_COMMENT("ID of the CGroup"),
                SD_VARLINK_DEFINE_FIELD(ID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path of the CGroup"),
                SD_VARLINK_DEFINE_FIELD(Path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),

                /* Memory */
                SD_VARLINK_FIELD_COMMENT("The current amount of memory used by the cgroup, in bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryCurrent, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The peak amount of memory used by the cgroup since its creation, in bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryPeak, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The current amount of swap space used by the cgroup, in bytes"),
                SD_VARLINK_DEFINE_FIELD(MemorySwapCurrent, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The peak amount of swap space used by the cgroup since its creation, in bytes"),
                SD_VARLINK_DEFINE_FIELD(MemorySwapPeak, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The current amount of zswap space used by the cgroup, in bytes"),
                SD_VARLINK_DEFINE_FIELD(MemoryZSwapCurrent, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The available memory for the cgroup, in bytes."),
                SD_VARLINK_DEFINE_FIELD(MemoryAvailable, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The effective maximum amount of memory allowed for the cgroup, in bytes"),
                SD_VARLINK_DEFINE_FIELD(EffectiveMemoryMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The effective high watermark for memory usage by the cgroup, in bytes"),
                SD_VARLINK_DEFINE_FIELD(EffectiveMemoryHigh, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Memory NUMA nodes that the cgroup is allowed to use"),
                SD_VARLINK_DEFINE_FIELD(EffectiveMemoryNodes, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* CPU */
                SD_VARLINK_FIELD_COMMENT("The total CPU usage time in nanoseconds (ns) for the cgroup"),
                SD_VARLINK_DEFINE_FIELD(CPUUsageNSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("NUMA nodes that the cgroup is allowed to use"),
                SD_VARLINK_DEFINE_FIELD(EffectiveCPUs, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The current number of tasks (i.e., processes or threads) running within the cgroup"),
                SD_VARLINK_DEFINE_FIELD(TasksCurrent, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The maximum number of tasks that the cgroup is allowed to run concurrently"),
                SD_VARLINK_DEFINE_FIELD(EffectiveTasksMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),

                /* IP */
                SD_VARLINK_FIELD_COMMENT("The total number of bytes received by the cgroup's IP stack"),
                SD_VARLINK_DEFINE_FIELD(IPIngressBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The total number of incoming packets received by the cgroup's IP stack"),
                SD_VARLINK_DEFINE_FIELD(IPIngressPackets, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("iThe total number of bytes sent by the cgroup's IP stack"),
                SD_VARLINK_DEFINE_FIELD(IPEgressBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The total number of outgoing packets sent by the cgroup's IP stack"),
                SD_VARLINK_DEFINE_FIELD(IPEgressPackets, SD_VARLINK_INT, SD_VARLINK_NULLABLE),

                /* IO */
                SD_VARLINK_FIELD_COMMENT("The total number of bytes read from block devices by the cgroup"),
                SD_VARLINK_DEFINE_FIELD(IOReadBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The total number of read operations performed on block devices by the cgroup"),
                SD_VARLINK_DEFINE_FIELD(IOReadOperations, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The total number of bytes written to block devices by the cgroup"),
                SD_VARLINK_DEFINE_FIELD(IOWriteBytes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The total number of write operations performed on block devices by the cgroup"),
                SD_VARLINK_DEFINE_FIELD(IOWriteOperations, SD_VARLINK_INT, SD_VARLINK_NULLABLE),

                /* OOM */
                SD_VARLINK_FIELD_COMMENT("The number of processes of this unit killed by the kernel OOM killer"),
                SD_VARLINK_DEFINE_FIELD(OOMKills, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The number of processes of this unit killed by systemd-oomd"),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMKills, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                UnitRuntime,
                SD_VARLINK_FIELD_COMMENT("If not empty, the field contains the name of another unit that this unit follows in state"),
                SD_VARLINK_DEFINE_FIELD(Following, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the configuration file of this unit has been loaded"),
                SD_VARLINK_DEFINE_FIELD(LoadState, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit is currently active or not"),
                SD_VARLINK_DEFINE_FIELD(ActiveState, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit is currently frozen or not"),
                SD_VARLINK_DEFINE_FIELD(FreezerState, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Reflect more fine-grained state that is unit-type-specific"),
                SD_VARLINK_DEFINE_FIELD(SubState, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Reflects the install state of the unit file"),
                SD_VARLINK_DEFINE_FIELD(UnitFileState, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when the firmware first began execution"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StateChangeTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when the unit entered active state"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ActiveEnterTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when the unit exited active state"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ActiveExitTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when the unit entered inactive state"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(InactiveEnterTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timestamp when the unit exited inactive state"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(InactiveExitTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit can be started or not"),
                SD_VARLINK_DEFINE_FIELD(CanStart, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit can be stopped or not"),
                SD_VARLINK_DEFINE_FIELD(CanStop, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit can be reloaded or not"),
                SD_VARLINK_DEFINE_FIELD(CanReload, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit may be started in isolation mode"),
                SD_VARLINK_DEFINE_FIELD(CanIsolate, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Returns which unit resources can be cleaned up"),
                SD_VARLINK_DEFINE_FIELD(CanClean, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the unit supports the freeze operation"),
                SD_VARLINK_DEFINE_FIELD(CanFreeze, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the unit supports live mounting"),
                SD_VARLINK_DEFINE_FIELD(CanLiveMount, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The job ID of the job currently scheduled or being executed for this unit, if there is any."),
                SD_VARLINK_DEFINE_FIELD(JobId, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the configuration file this unit is loaded from (i.e. FragmentPath or SourcePath) has changed since the configuration was read and hence whether a configuration reload is recommended"),
                SD_VARLINK_DEFINE_FIELD(NeedDaemonReload, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Condition result of the last time the configured conditions of this unit were checked"),
                SD_VARLINK_DEFINE_FIELD(ConditionResult, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Assert result of the last time the configured asserts of this unit were checked"),
                SD_VARLINK_DEFINE_FIELD(AssertResult, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The last time the configured conditions of the unit have been checked"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ConditionTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The last time the configured asserts of the unit have been checked"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(AssertTimestamp, Timestamp, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Current invocation ID"),
                SD_VARLINK_DEFINE_FIELD(InvocationID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit has been marked for reload, restart, etc."),
                SD_VARLINK_DEFINE_FIELD(Markers, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Provides details about why a unit was activated"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ActivationDetails, ActivationDetails, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The cgroup runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CGroup, CGroupRuntime, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("If non-null the name of a unit."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If non-null the PID of a unit. Special value 0 means to take pid of the caller."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(pid, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If non-null the cgroup of a unit"),
                SD_VARLINK_DEFINE_INPUT(cgroup, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If non-null the invocation ID of a unit"),
                SD_VARLINK_DEFINE_INPUT(invocationID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Configuration of the unit"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(context, UnitContext, 0),
                SD_VARLINK_FIELD_COMMENT("Runtime information of the unit"),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(runtime, UnitRuntime, 0));

static SD_VARLINK_DEFINE_ERROR(
                NoSuchUnit,
                SD_VARLINK_DEFINE_FIELD(parameter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(OnlyByDependency);
static SD_VARLINK_DEFINE_ERROR(DBusShuttingDown);
static SD_VARLINK_DEFINE_ERROR(UnitMasked);
static SD_VARLINK_DEFINE_ERROR(UnitError);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Unit,
                "io.systemd.Unit",
                SD_VARLINK_SYMBOL_COMMENT("List units"),
                &vl_method_List,
                &vl_type_RateLimit,
                SD_VARLINK_SYMBOL_COMMENT("An object to represent a unit's conditions"),
                &vl_type_Condition,
                SD_VARLINK_SYMBOL_COMMENT("An object to represent a unit's context"),
                &vl_type_UnitContext,
                SD_VARLINK_SYMBOL_COMMENT("An object to represent a unit's runtime information"),
                &vl_type_UnitRuntime,
                SD_VARLINK_SYMBOL_COMMENT("A timestamp object consisting of both CLOCK_REALTIME and CLOCK_MONOTONIC timestamps"),
                &vl_type_Timestamp,
                SD_VARLINK_SYMBOL_COMMENT("An object to represent a unit's activation details"),
                &vl_type_ActivationDetails,
                SD_VARLINK_SYMBOL_COMMENT("An object for referencing UNIX processes"),
                &vl_type_ProcessId,

                /* CGroupContext */
                &vl_type_CGroupTasksMax,
                &vl_type_CGroupIODeviceWeight,
                &vl_type_CGroupIODeviceLimit,
                &vl_type_CGroupIODeviceLatency,
                &vl_type_CGroupAddressPrefix,
                &vl_type_CGroupSocketBind,
                &vl_type_CGroupRestrictNetworkInterfaces,
                &vl_type_CGroupNFTSet,
                &vl_type_CGroupBPFProgram,
                &vl_type_CGroupDeviceAllow,
                SD_VARLINK_SYMBOL_COMMENT("CGroup context of a unit"),
                &vl_type_CGroupContext,
                SD_VARLINK_SYMBOL_COMMENT("CGroup runtime of a unit"),
                &vl_type_CGroupRuntime,

                /* ExecContext */
                &vl_type_WorkingDirectory,
                &vl_type_PartitionMountOptions,
                &vl_type_BindPath,
                &vl_type_MountImage,
                &vl_type_ExtensionImage,
                &vl_type_SELinuxContext,
                &vl_type_AppArmorProfile,
                &vl_type_SmackProcessLabel,
                &vl_type_ResourceLimit,
                &vl_type_ResourceLimitTable,
                &vl_type_CPUAffinity,
                &vl_type_ExecDirectoryQuota,
                &vl_type_ExecDirectoryPath,
                &vl_type_ExecDirectory,
                &vl_type_TemporaryFilesystem,
                &vl_type_AddressFamilyList,
                &vl_type_FilesystemList,
                &vl_type_SystemCallList,
                &vl_type_EnvironmentFile,
                &vl_type_LogFilterPattern,
                &vl_type_LoadCredential,
                &vl_type_ImportCredential,
                &vl_type_SetCredential,
                SD_VARLINK_SYMBOL_COMMENT("Exec context of a unit"),
                &vl_type_ExecContext,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("No matching unit found"),
                &vl_error_NoSuchUnit,
                SD_VARLINK_SYMBOL_COMMENT("The unit is masked"),
                &vl_error_UnitMasked,
                SD_VARLINK_SYMBOL_COMMENT("Unit is in a fatal error state"),
                &vl_error_UnitError,
                SD_VARLINK_SYMBOL_COMMENT("Job for the unit may only be enqueued by dependencies"),
                &vl_error_OnlyByDependency,
                SD_VARLINK_SYMBOL_COMMENT("A unit that requires D-Bus cannot be started as D-Bus is shutting down"),
                &vl_error_DBusShuttingDown);
