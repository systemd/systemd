/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-idl-common.h"
#include "varlink-io.systemd.Job.h"
#include "varlink-io.systemd.Unit.h"

SD_VARLINK_DEFINE_ENUM_TYPE(
                ExecInputType,
                SD_VARLINK_DEFINE_ENUM_VALUE(null),
                SD_VARLINK_DEFINE_ENUM_VALUE(tty),
                SD_VARLINK_DEFINE_ENUM_VALUE(tty_force),
                SD_VARLINK_DEFINE_ENUM_VALUE(tty_fail),
                SD_VARLINK_DEFINE_ENUM_VALUE(socket),
                SD_VARLINK_DEFINE_ENUM_VALUE(fd),
                SD_VARLINK_DEFINE_ENUM_VALUE(data),
                SD_VARLINK_DEFINE_ENUM_VALUE(file));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ExecUtmpMode,
                SD_VARLINK_DEFINE_ENUM_VALUE(init),
                SD_VARLINK_DEFINE_ENUM_VALUE(login),
                SD_VARLINK_DEFINE_ENUM_VALUE(user));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ExecPreserveMode,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_DEFINE_ENUM_VALUE(restart));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ExecKeyringMode,
                SD_VARLINK_DEFINE_ENUM_VALUE(inherit),
                SD_VARLINK_DEFINE_ENUM_VALUE(private),
                SD_VARLINK_DEFINE_ENUM_VALUE(shared));

SD_VARLINK_DEFINE_ENUM_TYPE(
                MemoryTHP,
                SD_VARLINK_DEFINE_ENUM_VALUE(inherit),
                SD_VARLINK_DEFINE_ENUM_VALUE(disable),
                SD_VARLINK_DEFINE_ENUM_VALUE(madvise),
                SD_VARLINK_DEFINE_ENUM_VALUE(system));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ProtectProc,
                SD_VARLINK_DEFINE_ENUM_VALUE(default),
                SD_VARLINK_DEFINE_ENUM_VALUE(noaccess),
                SD_VARLINK_DEFINE_ENUM_VALUE(invisible),
                SD_VARLINK_DEFINE_ENUM_VALUE(ptraceable));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ProcSubset,
                SD_VARLINK_DEFINE_ENUM_VALUE(all),
                SD_VARLINK_DEFINE_ENUM_VALUE(pid));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ProtectSystem,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_DEFINE_ENUM_VALUE(full),
                SD_VARLINK_DEFINE_ENUM_VALUE(strict));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ProtectHome,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_DEFINE_ENUM_VALUE(read_only),
                SD_VARLINK_DEFINE_ENUM_VALUE(tmpfs));

SD_VARLINK_DEFINE_ENUM_TYPE(
                PrivateTmp,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(connected),
                SD_VARLINK_DEFINE_ENUM_VALUE(disconnected));

SD_VARLINK_DEFINE_ENUM_TYPE(
                PrivateUsers,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(self),
                SD_VARLINK_DEFINE_ENUM_VALUE(identity),
                SD_VARLINK_DEFINE_ENUM_VALUE(full),
                SD_VARLINK_DEFINE_ENUM_VALUE(managed));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ProtectHostname,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_DEFINE_ENUM_VALUE(private));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ProtectControlGroups,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_DEFINE_ENUM_VALUE(private),
                SD_VARLINK_DEFINE_ENUM_VALUE(strict));

SD_VARLINK_DEFINE_ENUM_TYPE(
                PrivatePIDs,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes));

SD_VARLINK_DEFINE_ENUM_TYPE(
                CGroupDevicePolicy,
                SD_VARLINK_DEFINE_ENUM_VALUE(auto),
                SD_VARLINK_DEFINE_ENUM_VALUE(closed),
                SD_VARLINK_DEFINE_ENUM_VALUE(strict));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ManagedOOMPreference,
                SD_VARLINK_DEFINE_ENUM_VALUE(none),
                SD_VARLINK_DEFINE_ENUM_VALUE(avoid),
                SD_VARLINK_DEFINE_ENUM_VALUE(omit));

SD_VARLINK_DEFINE_ENUM_TYPE(
                CollectMode,
                SD_VARLINK_DEFINE_ENUM_VALUE(inactive),
                SD_VARLINK_DEFINE_ENUM_VALUE(inactive_or_failed));

SD_VARLINK_DEFINE_ENUM_TYPE(
                JobMode,
                SD_VARLINK_DEFINE_ENUM_VALUE(fail),
                SD_VARLINK_DEFINE_ENUM_VALUE(lenient),
                SD_VARLINK_DEFINE_ENUM_VALUE(replace),
                SD_VARLINK_DEFINE_ENUM_VALUE(replace_irreversibly),
                SD_VARLINK_DEFINE_ENUM_VALUE(isolate),
                SD_VARLINK_DEFINE_ENUM_VALUE(flush),
                SD_VARLINK_DEFINE_ENUM_VALUE(ignore_dependencies),
                SD_VARLINK_DEFINE_ENUM_VALUE(ignore_requirements),
                SD_VARLINK_DEFINE_ENUM_VALUE(triggering),
                SD_VARLINK_DEFINE_ENUM_VALUE(restart_dependencies));

SD_VARLINK_DEFINE_ENUM_TYPE(
                CGroupController,
                SD_VARLINK_DEFINE_ENUM_VALUE(cpu),
                SD_VARLINK_DEFINE_ENUM_VALUE(cpuacct),
                SD_VARLINK_DEFINE_ENUM_VALUE(cpuset),
                SD_VARLINK_DEFINE_ENUM_VALUE(io),
                SD_VARLINK_DEFINE_ENUM_VALUE(blkio),
                SD_VARLINK_DEFINE_ENUM_VALUE(memory),
                SD_VARLINK_DEFINE_ENUM_VALUE(devices),
                SD_VARLINK_DEFINE_ENUM_VALUE(pids),
                SD_VARLINK_DEFINE_ENUM_VALUE(bpf_firewall),
                SD_VARLINK_DEFINE_ENUM_VALUE(bpf_devices),
                SD_VARLINK_DEFINE_ENUM_VALUE(bpf_foreign),
                SD_VARLINK_DEFINE_ENUM_VALUE(bpf_socket_bind),
                SD_VARLINK_DEFINE_ENUM_VALUE(bpf_restrict_network_interfaces),
                SD_VARLINK_DEFINE_ENUM_VALUE(bpf_bind_network_interface));

SD_VARLINK_DEFINE_ENUM_TYPE(
                PrivateBPF,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes));

SD_VARLINK_DEFINE_ENUM_TYPE(
                CPUSchedulingPolicy,
                SD_VARLINK_DEFINE_ENUM_VALUE(other),
                SD_VARLINK_DEFINE_ENUM_VALUE(batch),
                SD_VARLINK_DEFINE_ENUM_VALUE(idle),
                SD_VARLINK_DEFINE_ENUM_VALUE(fifo),
                SD_VARLINK_DEFINE_ENUM_VALUE(ext),
                SD_VARLINK_DEFINE_ENUM_VALUE(rr));

SD_VARLINK_DEFINE_ENUM_TYPE(
                IOSchedulingClass,
                SD_VARLINK_DEFINE_ENUM_VALUE(none),
                SD_VARLINK_DEFINE_ENUM_VALUE(realtime),
                SD_VARLINK_DEFINE_ENUM_VALUE(best_effort),
                SD_VARLINK_DEFINE_ENUM_VALUE(idle));

SD_VARLINK_DEFINE_ENUM_TYPE(
                NUMAPolicy,
                SD_VARLINK_DEFINE_ENUM_VALUE(default),
                SD_VARLINK_DEFINE_ENUM_VALUE(preferred),
                SD_VARLINK_DEFINE_ENUM_VALUE(bind),
                SD_VARLINK_DEFINE_ENUM_VALUE(interleave),
                SD_VARLINK_DEFINE_ENUM_VALUE(local));

SD_VARLINK_DEFINE_ENUM_TYPE(
                MountPropagationFlag,
                SD_VARLINK_DEFINE_ENUM_VALUE(shared),
                SD_VARLINK_DEFINE_ENUM_VALUE(slave),
                SD_VARLINK_DEFINE_ENUM_VALUE(private));

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
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#BindNetworkInterface="),
                SD_VARLINK_DEFINE_FIELD(BindNetworkInterface, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(DevicePolicy, CGroupDevicePolicy, 0),

                /* Control Group Management
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Control%20Group%20Management */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#Delegate="),
                SD_VARLINK_DEFINE_FIELD(Delegate, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DelegateSubgroup="),
                SD_VARLINK_DEFINE_FIELD(DelegateSubgroup, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DisableControllers="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(DelegateControllers, CGroupController, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#DisableControllers="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(DisableControllers, CGroupController, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),

                /* Memory Pressure Control
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html#Memory%20Pressure%20Control */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMSwap=auto%7Ckill"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ManagedOOMSwap, ManagedOOMMode, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMSwap=auto%7Ckill"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ManagedOOMMemoryPressure, ManagedOOMMode, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMMemoryPressureLimit="),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMMemoryPressureLimit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMMemoryPressureDurationSec="),
                SD_VARLINK_DEFINE_FIELD(ManagedOOMMemoryPressureDurationUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#ManagedOOMPreference=none%7Cavoid%7Comit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ManagedOOMPreference, ManagedOOMPreference, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryPressureWatch="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(MemoryPressureWatch, CGroupPressureWatch, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#MemoryPressureThresholdSec="),
                SD_VARLINK_DEFINE_FIELD(MemoryPressureThresholdUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#CPUPressureWatch="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CPUPressureWatch, CGroupPressureWatch, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#CPUPressureThresholdSec="),
                SD_VARLINK_DEFINE_FIELD(CPUPressureThresholdUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOPressureWatch="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IOPressureWatch, CGroupPressureWatch, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.resource-control.html#IOPressureThresholdSec="),
                SD_VARLINK_DEFINE_FIELD(IOPressureThresholdUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),

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
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RootMStack="),
                SD_VARLINK_DEFINE_FIELD(RootMStack, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ProtectProc, ProtectProc, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProcSubset="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ProcSubset, ProcSubset, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(KeyringMode, ExecKeyringMode, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CPUSchedulingPolicy, CPUSchedulingPolicy, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUSchedulingPriority="),
                SD_VARLINK_DEFINE_FIELD(CPUSchedulingPriority, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUSchedulingResetOnFork="),
                SD_VARLINK_DEFINE_FIELD(CPUSchedulingResetOnFork, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#CPUAffinity="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CPUAffinity, CPUAffinity, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#NUMAPolicy="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(NUMAPolicy, NUMAPolicy, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#NUMAMask="),
                SD_VARLINK_DEFINE_FIELD(NUMAMask, SD_VARLINK_INT, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#IOSchedulingClass="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(IOSchedulingClass, IOSchedulingClass, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#IOSchedulingPriority="),
                SD_VARLINK_DEFINE_FIELD(IOSchedulingPriority, SD_VARLINK_INT, 0),

                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MemoryKSM="),
                SD_VARLINK_DEFINE_FIELD(MemoryKSM, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#MemoryTHP="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(MemoryTHP, MemoryTHP, 0),

                /* Sandboxing
                 * https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html#Sandboxing */
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectSystem="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ProtectSystem, ProtectSystem, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectHome="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ProtectHome, ProtectHome, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RuntimeDirectoryPreserve, ExecPreserveMode, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(PrivateTmp, PrivateTmp, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(PrivatePIDs, PrivatePIDs, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivateUsers="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(PrivateUsers, PrivateUsers, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#UserNamespacePath="),
                SD_VARLINK_DEFINE_FIELD(UserNamespacePath, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectHostname="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ProtectHostname, ProtectHostname, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectClock="),
                SD_VARLINK_DEFINE_FIELD(ProtectClock, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectKernelTunables="),
                SD_VARLINK_DEFINE_FIELD(ProtectKernelTunables, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectKernelModules="),
                SD_VARLINK_DEFINE_FIELD(ProtectKernelModules, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectKernelLogs="),
                SD_VARLINK_DEFINE_FIELD(ProtectKernelLogs, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#ProtectControlGroups="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ProtectControlGroups, ProtectControlGroups, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictAddressFamilies="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RestrictAddressFamilies, AddressFamilyList, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictFileSystems="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(RestrictFilesystems, FilesystemList, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#RestrictNamespaces="),
                SD_VARLINK_DEFINE_FIELD(RestrictNamespaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#DelegateNamespaces="),
                SD_VARLINK_DEFINE_FIELD(DelegateNamespaces, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#PrivatePBF="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(PrivatePBF, PrivateBPF, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(MountFlags, MountPropagationFlag, SD_VARLINK_NULLABLE),

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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StandardInput, ExecInputType, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#StandardOutput="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StandardOutput, ExecOutputType, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man"PROJECT_VERSION_STR"systemd.exec.html#StandardError="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StandardError, ExecOutputType, 0),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(UtmpMode, ExecUtmpMode, 0));

SD_VARLINK_DEFINE_ENUM_TYPE(
                KillMode,
                SD_VARLINK_DEFINE_ENUM_VALUE(control_group),
                SD_VARLINK_DEFINE_ENUM_VALUE(process),
                SD_VARLINK_DEFINE_ENUM_VALUE(mixed),
                SD_VARLINK_DEFINE_ENUM_VALUE(none));

/* KillContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.kill.html */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                KillContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#KillMode="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(KillMode, KillMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#KillSignal="),
                SD_VARLINK_DEFINE_FIELD(KillSignal, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#RestartKillSignal="),
                SD_VARLINK_DEFINE_FIELD(RestartKillSignal, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#SendSIGHUP="),
                SD_VARLINK_DEFINE_FIELD(SendSIGHUP, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#SendSIGKILL="),
                SD_VARLINK_DEFINE_FIELD(SendSIGKILL, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#FinalKillSignal="),
                SD_VARLINK_DEFINE_FIELD(FinalKillSignal, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.kill.html#WatchdogSignal="),
                SD_VARLINK_DEFINE_FIELD(WatchdogSignal, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

/* AutomountContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.automount.html */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                AutomountContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.automount.html#Where="),
                SD_VARLINK_DEFINE_FIELD(Where, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.automount.html#ExtraOptions="),
                SD_VARLINK_DEFINE_FIELD(ExtraOptions, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.automount.html#DirectoryMode="),
                SD_VARLINK_DEFINE_FIELD(DirectoryMode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.automount.html#TimeoutIdleSec="),
                SD_VARLINK_DEFINE_FIELD(TimeoutIdleUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

/* MountContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.mount.html */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                MountContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#What="),
                SD_VARLINK_DEFINE_FIELD(What, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#Where="),
                SD_VARLINK_DEFINE_FIELD(Where, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#Type="),
                SD_VARLINK_DEFINE_FIELD(Type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#Options="),
                SD_VARLINK_DEFINE_FIELD(Options, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#SloppyOptions="),
                SD_VARLINK_DEFINE_FIELD(SloppyOptions, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#LazyUnmount="),
                SD_VARLINK_DEFINE_FIELD(LazyUnmount, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#ReadWriteOnly="),
                SD_VARLINK_DEFINE_FIELD(ReadWriteOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#ForceUnmount="),
                SD_VARLINK_DEFINE_FIELD(ForceUnmount, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#DirectoryMode="),
                SD_VARLINK_DEFINE_FIELD(DirectoryMode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.mount.html#TimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(TimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Mount command"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecMount, ExecCommand, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Unmount command"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecUnmount, ExecCommand, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Remount command"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecRemount, ExecCommand, SD_VARLINK_NULLABLE));

/* PathContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.path.html */
SD_VARLINK_DEFINE_ENUM_TYPE(
                PathType,
                SD_VARLINK_DEFINE_ENUM_VALUE(PathExists),
                SD_VARLINK_DEFINE_ENUM_VALUE(PathExistsGlob),
                SD_VARLINK_DEFINE_ENUM_VALUE(DirectoryNotEmpty),
                SD_VARLINK_DEFINE_ENUM_VALUE(PathChanged),
                SD_VARLINK_DEFINE_ENUM_VALUE(PathModified));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PathSpec,
                SD_VARLINK_FIELD_COMMENT("Path spec type"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(type, PathType, 0),
                SD_VARLINK_FIELD_COMMENT("Path"),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PathContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.path.html#PathExists="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Paths, PathSpec, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.path.html#Unit="),
                SD_VARLINK_DEFINE_FIELD(Unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.path.html#MakeDirectory="),
                SD_VARLINK_DEFINE_FIELD(MakeDirectory, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.path.html#DirectoryMode="),
                SD_VARLINK_DEFINE_FIELD(DirectoryMode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.path.html#TriggerLimitIntervalSec="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(TriggerLimit, RateLimit, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_ENUM_TYPE(
                PathResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(start_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(unit_start_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(trigger_limit_hit));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                PathRuntime,
                SD_VARLINK_FIELD_COMMENT("Result of path operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, PathResult, 0));

/* ScopeContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.scope.html */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ScopeContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.scope.html#OOMPolicy="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(OOMPolicy, OOMPolicy, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.scope.html#RuntimeMaxSec="),
                SD_VARLINK_DEFINE_FIELD(RuntimeMaxUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.scope.html#RuntimeRandomizedExtraSec="),
                SD_VARLINK_DEFINE_FIELD(RuntimeRandomizedExtraUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.scope.html#TimeoutStopSec="),
                SD_VARLINK_DEFINE_FIELD(TimeoutStopUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ScopeResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(timeout),
                SD_VARLINK_DEFINE_ENUM_VALUE(oom_kill));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ScopeRuntime,
                SD_VARLINK_FIELD_COMMENT("Result of scope operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, ScopeResult, 0));

/* SocketContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.socket.html */
SD_VARLINK_DEFINE_ENUM_TYPE(
                SocketBindIPv6Only,
                SD_VARLINK_DEFINE_ENUM_VALUE(default),
                SD_VARLINK_DEFINE_ENUM_VALUE(both),
                SD_VARLINK_DEFINE_ENUM_VALUE(ipv6_only));

SD_VARLINK_DEFINE_ENUM_TYPE(
                SocketTimestamping,
                SD_VARLINK_DEFINE_ENUM_VALUE(off),
                SD_VARLINK_DEFINE_ENUM_VALUE(us),
                SD_VARLINK_DEFINE_ENUM_VALUE(ns));

SD_VARLINK_DEFINE_ENUM_TYPE(
                SocketDeferTrigger,
                SD_VARLINK_DEFINE_ENUM_VALUE(no),
                SD_VARLINK_DEFINE_ENUM_VALUE(yes),
                SD_VARLINK_DEFINE_ENUM_VALUE(patient));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SocketListen,
                SD_VARLINK_FIELD_COMMENT("Socket type"),
                SD_VARLINK_DEFINE_FIELD(type, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Socket address"),
                SD_VARLINK_DEFINE_FIELD(address, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SocketContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ListenStream="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Listen, SocketListen, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SocketProtocol="),
                SD_VARLINK_DEFINE_FIELD(SocketProtocol, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#BindIPv6Only="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(BindIPv6Only, SocketBindIPv6Only, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Backlog="),
                SD_VARLINK_DEFINE_FIELD(Backlog, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#BindToDevice="),
                SD_VARLINK_DEFINE_FIELD(BindToDevice, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SocketUser="),
                SD_VARLINK_DEFINE_FIELD(SocketUser, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SocketUser="),
                SD_VARLINK_DEFINE_FIELD(SocketGroup, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SocketMode="),
                SD_VARLINK_DEFINE_FIELD(SocketMode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#DirectoryMode="),
                SD_VARLINK_DEFINE_FIELD(DirectoryMode, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Accept="),
                SD_VARLINK_DEFINE_FIELD(Accept, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Writable="),
                SD_VARLINK_DEFINE_FIELD(Writable, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#FlushPending="),
                SD_VARLINK_DEFINE_FIELD(FlushPending, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#MaxConnections="),
                SD_VARLINK_DEFINE_FIELD(MaxConnections, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#MaxConnectionsPerSource="),
                SD_VARLINK_DEFINE_FIELD(MaxConnectionsPerSource, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#KeepAlive="),
                SD_VARLINK_DEFINE_FIELD(KeepAlive, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#KeepAliveTimeSec="),
                SD_VARLINK_DEFINE_FIELD(KeepAliveTimeUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#KeepAliveIntervalSec="),
                SD_VARLINK_DEFINE_FIELD(KeepAliveIntervalUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#KeepAliveProbes="),
                SD_VARLINK_DEFINE_FIELD(KeepAliveProbes, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#NoDelay="),
                SD_VARLINK_DEFINE_FIELD(NoDelay, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Priority="),
                SD_VARLINK_DEFINE_FIELD(Priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#DeferAcceptSec="),
                SD_VARLINK_DEFINE_FIELD(DeferAcceptUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ReceiveBuffer="),
                SD_VARLINK_DEFINE_FIELD(ReceiveBuffer, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SendBuffer="),
                SD_VARLINK_DEFINE_FIELD(SendBuffer, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#IPTOS="),
                SD_VARLINK_DEFINE_FIELD(IPTOS, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#IPTTL="),
                SD_VARLINK_DEFINE_FIELD(IPTTL, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Mark="),
                SD_VARLINK_DEFINE_FIELD(Mark, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ReusePort="),
                SD_VARLINK_DEFINE_FIELD(ReusePort, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SmackLabel="),
                SD_VARLINK_DEFINE_FIELD(SmackLabel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SmackLabelIPIn="),
                SD_VARLINK_DEFINE_FIELD(SmackLabelIPIn, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SmackLabelIPOut="),
                SD_VARLINK_DEFINE_FIELD(SmackLabelIPOut, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#SELinuxContextFromNet="),
                SD_VARLINK_DEFINE_FIELD(SELinuxContextFromNet, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PipeSize="),
                SD_VARLINK_DEFINE_FIELD(PipeSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#MessageQueueMaxMessages="),
                SD_VARLINK_DEFINE_FIELD(MessageQueueMaxMessages, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#MessageQueueMessageSize="),
                SD_VARLINK_DEFINE_FIELD(MessageQueueMessageSize, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#FreeBind="),
                SD_VARLINK_DEFINE_FIELD(FreeBind, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Transparent="),
                SD_VARLINK_DEFINE_FIELD(Transparent, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Broadcast="),
                SD_VARLINK_DEFINE_FIELD(Broadcast, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PassCredentials="),
                SD_VARLINK_DEFINE_FIELD(PassCredentials, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PassPIDFD="),
                SD_VARLINK_DEFINE_FIELD(PassPIDFD, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PassSecurity="),
                SD_VARLINK_DEFINE_FIELD(PassSecurity, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PassPacketInfo="),
                SD_VARLINK_DEFINE_FIELD(PassPacketInfo, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#AcceptFileDescriptors="),
                SD_VARLINK_DEFINE_FIELD(AcceptFileDescriptors, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Timestamping="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Timestamping, SocketTimestamping, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#TCPCongestion="),
                SD_VARLINK_DEFINE_FIELD(TCPCongestion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ExecStartPre="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecStartPre, ExecCommand, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ExecStartPost="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecStartPost, ExecCommand, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ExecStopPre="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecStopPre, ExecCommand, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#ExecStopPost="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecStopPost, ExecCommand, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#TimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(TimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#RemoveOnStop="),
                SD_VARLINK_DEFINE_FIELD(RemoveOnStop, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#Symlinks="),
                SD_VARLINK_DEFINE_FIELD(Symlinks, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#FileDescriptorName="),
                SD_VARLINK_DEFINE_FIELD(FileDescriptorName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#TriggerLimitIntervalSec="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(TriggerLimit, RateLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PollLimitIntervalSec="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(PollLimit, RateLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#DeferTrigger="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(DeferTrigger, SocketDeferTrigger, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#DeferTriggerMaxSec="),
                SD_VARLINK_DEFINE_FIELD(DeferTriggerMaxUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.socket.html#PassFileDescriptorsToExec="),
                SD_VARLINK_DEFINE_FIELD(PassFileDescriptorsToExec, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_ENUM_TYPE(
                SocketResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(timeout),
                SD_VARLINK_DEFINE_ENUM_VALUE(exit_code),
                SD_VARLINK_DEFINE_ENUM_VALUE(signal),
                SD_VARLINK_DEFINE_ENUM_VALUE(core_dump),
                SD_VARLINK_DEFINE_ENUM_VALUE(start_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(trigger_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(service_start_limit_hit));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SocketRuntime,
                SD_VARLINK_FIELD_COMMENT("PID of the current socket control process"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ControlPID, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Result of socket operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, SocketResult, 0),
                SD_VARLINK_FIELD_COMMENT("Result of cleaning operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CleanResult, SocketResult, 0),
                SD_VARLINK_FIELD_COMMENT("Number of current connections"),
                SD_VARLINK_DEFINE_FIELD(NConnections, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Number of accepted connections"),
                SD_VARLINK_DEFINE_FIELD(NAccepted, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Number of refused connections"),
                SD_VARLINK_DEFINE_FIELD(NRefused, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reference UID"),
                SD_VARLINK_DEFINE_FIELD(UID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reference GID"),
                SD_VARLINK_DEFINE_FIELD(GID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

/* SwapContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.swap.html */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SwapContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.swap.html#What="),
                SD_VARLINK_DEFINE_FIELD(What, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.swap.html#Priority="),
                SD_VARLINK_DEFINE_FIELD(Priority, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.swap.html#Options="),
                SD_VARLINK_DEFINE_FIELD(Options, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.swap.html#TimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(TimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Activate command"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecActivate, ExecCommand, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Deactivate command"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecDeactivate, ExecCommand, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_ENUM_TYPE(
                SwapResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(timeout),
                SD_VARLINK_DEFINE_ENUM_VALUE(exit_code),
                SD_VARLINK_DEFINE_ENUM_VALUE(signal),
                SD_VARLINK_DEFINE_ENUM_VALUE(core_dump),
                SD_VARLINK_DEFINE_ENUM_VALUE(start_limit_hit));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                SwapRuntime,
                SD_VARLINK_FIELD_COMMENT("PID of the current swap control process"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ControlPID, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Result of swap operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, SwapResult, 0),
                SD_VARLINK_FIELD_COMMENT("Result of cleaning operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CleanResult, SwapResult, 0),
                SD_VARLINK_FIELD_COMMENT("Reference UID"),
                SD_VARLINK_DEFINE_FIELD(UID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reference GID"),
                SD_VARLINK_DEFINE_FIELD(GID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

/* TimerContext
 * https://www.freedesktop.org/software/systemd/man/latest/systemd.timer.html */
SD_VARLINK_DEFINE_ENUM_TYPE(
                TimerBase,
                SD_VARLINK_DEFINE_ENUM_VALUE(OnActiveUSec),
                SD_VARLINK_DEFINE_ENUM_VALUE(OnBootUSec),
                SD_VARLINK_DEFINE_ENUM_VALUE(OnStartupUSec),
                SD_VARLINK_DEFINE_ENUM_VALUE(OnUnitActiveUSec),
                SD_VARLINK_DEFINE_ENUM_VALUE(OnUnitInactiveUSec),
                SD_VARLINK_DEFINE_ENUM_VALUE(OnCalendar));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TimerSpec,
                SD_VARLINK_FIELD_COMMENT("Timer base type"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(base, TimerBase, 0),
                SD_VARLINK_FIELD_COMMENT("Timer value in microseconds (for monotonic timers)"),
                SD_VARLINK_DEFINE_FIELD(usec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Calendar specification string (for calendar timers)"),
                SD_VARLINK_DEFINE_FIELD(calendar, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TimerContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#OnActiveSec="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Timers, TimerSpec, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#Unit="),
                SD_VARLINK_DEFINE_FIELD(Unit, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#OnClockChange="),
                SD_VARLINK_DEFINE_FIELD(OnClockChange, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#OnClockChange="),
                SD_VARLINK_DEFINE_FIELD(OnTimezoneChange, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#AccuracySec="),
                SD_VARLINK_DEFINE_FIELD(AccuracyUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#RandomizedDelaySec="),
                SD_VARLINK_DEFINE_FIELD(RandomizedDelayUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#RandomizedOffsetSec="),
                SD_VARLINK_DEFINE_FIELD(RandomizedOffsetUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#FixedRandomDelay="),
                SD_VARLINK_DEFINE_FIELD(FixedRandomDelay, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#Persistent="),
                SD_VARLINK_DEFINE_FIELD(Persistent, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#WakeSystem="),
                SD_VARLINK_DEFINE_FIELD(WakeSystem, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#RemainAfterElapse="),
                SD_VARLINK_DEFINE_FIELD(RemainAfterElapse, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.timer.html#DeferReactivation="),
                SD_VARLINK_DEFINE_FIELD(DeferReactivation, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_ENUM_TYPE(
                TimerResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(start_limit_hit));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TimerRuntime,
                SD_VARLINK_FIELD_COMMENT("Result of timer operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, TimerResult, 0),
                SD_VARLINK_FIELD_COMMENT("Next elapse time in realtime clock"),
                SD_VARLINK_DEFINE_FIELD(NextElapseUSecRealtime, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Next elapse time in monotonic clock"),
                SD_VARLINK_DEFINE_FIELD(NextElapseUSecMonotonic, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Last time the timer triggered"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(LastTriggerUSec, Timestamp, SD_VARLINK_NULLABLE));

/* Service-specific types */

/* Keep in sync with service_type_table[] in src/core/service.c */
SD_VARLINK_DEFINE_ENUM_TYPE(
                ServiceType,
                SD_VARLINK_DEFINE_ENUM_VALUE(simple),
                SD_VARLINK_DEFINE_ENUM_VALUE(exec),
                SD_VARLINK_DEFINE_ENUM_VALUE(forking),
                SD_VARLINK_DEFINE_ENUM_VALUE(oneshot),
                SD_VARLINK_DEFINE_ENUM_VALUE(dbus),
                SD_VARLINK_DEFINE_ENUM_VALUE(notify),
                SD_VARLINK_FIELD_COMMENT("Like notify, but also implements a reload protocol via SIGHUP."),
                SD_VARLINK_DEFINE_ENUM_VALUE(notify_reload),
                SD_VARLINK_DEFINE_ENUM_VALUE(idle));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ServiceContext,
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.service.html#Type="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Type, ServiceType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.service.html#ExecStart="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ExecStart, ExecCommand, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.service.html#RemainAfterExit="),
                SD_VARLINK_DEFINE_FIELD(RemainAfterExit, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

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

/* UnitContext is used both as input to StartTransient (subset settable at creation time: ID,
 * Description, Service) and as output from List/StartTransient (full unit configuration). Fields that
 * are not settable at creation time are rejected with PropertyNotSupported when supplied as input. */
static SD_VARLINK_DEFINE_STRUCT_TYPE(
                UnitContext,
                SD_VARLINK_FIELD_COMMENT("The unit type"),
                SD_VARLINK_DEFINE_FIELD(Type, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(OnSuccessJobMode, JobMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#OnSuccessJobMode="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(OnFailureJobMode, JobMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#IgnoreOnIsolate="),
                SD_VARLINK_DEFINE_FIELD(IgnoreOnIsolate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#StopWhenUnneeded="),
                SD_VARLINK_DEFINE_FIELD(StopWhenUnneeded, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#RefuseManualStart="),
                SD_VARLINK_DEFINE_FIELD(RefuseManualStart, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#RefuseManualStart="),
                SD_VARLINK_DEFINE_FIELD(RefuseManualStop, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#AllowIsolate="),
                SD_VARLINK_DEFINE_FIELD(AllowIsolate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#DefaultDependencies="),
                SD_VARLINK_DEFINE_FIELD(DefaultDependencies, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#SurviveFinalKillSignal="),
                SD_VARLINK_DEFINE_FIELD(SurviveFinalKillSignal, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#CollectMode="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CollectMode, CollectMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureAction="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(FailureAction, EmergencyAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureAction="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(SuccessAction, EmergencyAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureActionExitStatus="),
                SD_VARLINK_DEFINE_FIELD(FailureActionExitStatus, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#FailureActionExitStatus="),
                SD_VARLINK_DEFINE_FIELD(SuccessActionExitStatus, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(JobTimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutSec="),
                SD_VARLINK_DEFINE_FIELD(JobRunningTimeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutAction="),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(JobTimeoutAction, EmergencyAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#JobTimeoutAction="),
                SD_VARLINK_DEFINE_FIELD(JobTimeoutRebootArgument, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#StartLimitIntervalSec=interval"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StartLimit, RateLimit, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("https://www.freedesktop.org/software/systemd/man/"PROJECT_VERSION_STR"/systemd.unit.html#StartLimitIntervalSec=interval"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(StartLimitAction, EmergencyAction, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD(Transient, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether this unit is perpetual"),
                SD_VARLINK_DEFINE_FIELD(Perpetual, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("When true, logs about this unit will be at debug level regardless of other log level settings"),
                SD_VARLINK_DEFINE_FIELD(DebugInvocation, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),

                /* Other contexts */
                SD_VARLINK_FIELD_COMMENT("The cgroup context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CGroup, CGroupContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The exec context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Exec, ExecContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The kill context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Kill, KillContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The service context of the unit (only for .service units)"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Service, ServiceContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The automount context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Automount, AutomountContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The mount context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Mount, MountContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The path context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Path, PathContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The scope context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Scope, ScopeContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The socket context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Socket, SocketContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The swap context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Swap, SwapContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The timer context of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Timer, TimerContext, SD_VARLINK_NULLABLE));

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

SD_VARLINK_DEFINE_ENUM_TYPE(
                AutomountResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(start_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(mount_start_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(unmounted));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                AutomountRuntime,
                SD_VARLINK_FIELD_COMMENT("Result of automount operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, AutomountResult, 0));

SD_VARLINK_DEFINE_ENUM_TYPE(
                MountResult,
                SD_VARLINK_DEFINE_ENUM_VALUE(success),
                SD_VARLINK_DEFINE_ENUM_VALUE(resources),
                SD_VARLINK_DEFINE_ENUM_VALUE(timeout),
                SD_VARLINK_DEFINE_ENUM_VALUE(exit_code),
                SD_VARLINK_DEFINE_ENUM_VALUE(signal),
                SD_VARLINK_DEFINE_ENUM_VALUE(core_dump),
                SD_VARLINK_DEFINE_ENUM_VALUE(start_limit_hit),
                SD_VARLINK_DEFINE_ENUM_VALUE(protocol));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                MountRuntime,
                SD_VARLINK_FIELD_COMMENT("PID of the current mount/remount/etc process running"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ControlPID, ProcessId, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Result of mount operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Result, MountResult, 0),
                SD_VARLINK_FIELD_COMMENT("Result of remount operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(ReloadResult, MountResult, 0),
                SD_VARLINK_FIELD_COMMENT("Result of cleaning operation"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CleanResult, MountResult, 0),
                SD_VARLINK_FIELD_COMMENT("Reference UID"),
                SD_VARLINK_DEFINE_FIELD(UID, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reference GID"),
                SD_VARLINK_DEFINE_FIELD(GID, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                UnitRuntime,
                SD_VARLINK_FIELD_COMMENT("If not empty, the field contains the name of another unit that this unit follows in state"),
                SD_VARLINK_DEFINE_FIELD(Following, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the configuration file of this unit has been loaded"),
                SD_VARLINK_DEFINE_FIELD(LoadState, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit is currently active or not"),
                SD_VARLINK_DEFINE_FIELD(ActiveState, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit is currently frozen or not"),
                SD_VARLINK_DEFINE_FIELD(FreezerState, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflect more fine-grained state that is unit-type-specific"),
                SD_VARLINK_DEFINE_FIELD(SubState, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD(CanStart, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit can be stopped or not"),
                SD_VARLINK_DEFINE_FIELD(CanStop, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit can be reloaded or not"),
                SD_VARLINK_DEFINE_FIELD(CanReload, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Reflects whether the unit may be started in isolation mode"),
                SD_VARLINK_DEFINE_FIELD(CanIsolate, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Returns which unit resources can be cleaned up"),
                SD_VARLINK_DEFINE_FIELD(CanClean, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the unit supports the freeze operation"),
                SD_VARLINK_DEFINE_FIELD(CanFreeze, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the unit supports live mounting"),
                SD_VARLINK_DEFINE_FIELD(CanLiveMount, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The job ID of the job currently scheduled or being executed for this unit, if there is any."),
                SD_VARLINK_DEFINE_FIELD(JobId, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the configuration file this unit is loaded from (i.e. FragmentPath or SourcePath) has changed since the configuration was read and hence whether a configuration reload is recommended"),
                SD_VARLINK_DEFINE_FIELD(NeedDaemonReload, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Condition result of the last time the configured conditions of this unit were checked"),
                SD_VARLINK_DEFINE_FIELD(ConditionResult, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Assert result of the last time the configured asserts of this unit were checked"),
                SD_VARLINK_DEFINE_FIELD(AssertResult, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
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
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(CGroup, CGroupRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The automount runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Automount, AutomountRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The mount runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Mount, MountRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The path runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Path, PathRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The scope runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Scope, ScopeRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The socket runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Socket, SocketRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The swap runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Swap, SwapRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The timer runtime of the unit"),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(Timer, TimerRuntime, SD_VARLINK_NULLABLE));

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
static SD_VARLINK_DEFINE_ERROR(
                PropertyNotSupported,
                SD_VARLINK_DEFINE_FIELD(property, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(UnitExists);
static SD_VARLINK_DEFINE_ERROR(UnitTypeNotSupported);
static SD_VARLINK_DEFINE_ERROR(BadUnitSetting);

static SD_VARLINK_DEFINE_METHOD_FULL(
                StartTransient,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Unit context. Must include ID (the unit name). Only the subset of fields settable at creation time is accepted; supplying any other field returns PropertyNotSupported."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(context, UnitContext, 0),
                SD_VARLINK_FIELD_COMMENT("Job mode. Defaults to replace."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(mode, JobMode, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true and 'more' is set, stream job state change notifications. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(notifyJobChanges, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If true and 'more' is set, stream unit runtime notifications on state changes. Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(notifyUnitChanges, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Unit context. Set in the final reply."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(context, UnitContext, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Unit runtime state. Set in the final reply and in intermediate streaming notifications when notifyUnitChanges is true."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(runtime, UnitRuntime, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The job that was enqueued. Always set in the final streaming reply; also included in intermediate streaming notifications when notifyJobChanges is true."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(job, Job, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                SetProperties,
                SD_VARLINK_FIELD_COMMENT("The name of the unit to operate on."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Whether to apply the change ephemerally or persistently."),
                SD_VARLINK_DEFINE_INPUT(runtime, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("The runtime properties to set."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(properties, UnitRuntime, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_Unit,
                "io.systemd.Unit",
                SD_VARLINK_SYMBOL_COMMENT("List units"),
                &vl_method_List,
                SD_VARLINK_SYMBOL_COMMENT("Set unit properties"),
                &vl_method_SetProperties,
                SD_VARLINK_SYMBOL_COMMENT("Create a transient unit and start it"),
                &vl_method_StartTransient,
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
                &vl_type_CGroupDevicePolicy,
                &vl_type_ManagedOOMMode,
                &vl_type_ManagedOOMPreference,
                &vl_type_CGroupPressureWatch,
                &vl_type_CGroupTasksMax,
                &vl_type_CGroupIODeviceWeight,
                &vl_type_CGroupIODeviceLimit,
                &vl_type_CGroupIODeviceLatency,
                &vl_type_CGroupAddressPrefix,
                &vl_type_CGroupSocketBind,
                &vl_type_CGroupRestrictNetworkInterfaces,
                &vl_type_CGroupNFTSet,
                &vl_type_CGroupBPFProgram,
                &vl_type_CGroupController,
                &vl_type_CGroupDeviceAllow,
                SD_VARLINK_SYMBOL_COMMENT("CGroup context of a unit"),
                &vl_type_CGroupContext,
                SD_VARLINK_SYMBOL_COMMENT("CGroup runtime of a unit"),
                &vl_type_CGroupRuntime,

                /* ExecContext */
                &vl_type_ExecInputType,
                &vl_type_ExecOutputType,
                &vl_type_ExecUtmpMode,
                &vl_type_ExecPreserveMode,
                &vl_type_ExecKeyringMode,
                &vl_type_MemoryTHP,
                &vl_type_ProtectProc,
                &vl_type_ProcSubset,
                &vl_type_ProtectSystem,
                &vl_type_ProtectHome,
                &vl_type_PrivateTmp,
                &vl_type_PrivateUsers,
                &vl_type_ProtectHostname,
                &vl_type_ProtectControlGroups,
                &vl_type_PrivatePIDs,
                &vl_type_PrivateBPF,
                &vl_type_CPUSchedulingPolicy,
                &vl_type_IOSchedulingClass,
                &vl_type_NUMAPolicy,
                &vl_type_MountPropagationFlag,
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

                /* other contexts */
                &vl_type_KillMode,
                &vl_type_KillContext,
                &vl_type_AutomountContext,
                &vl_type_AutomountResult,
                &vl_type_AutomountRuntime,
                &vl_type_ExecCommand,
                &vl_type_MountContext,
                &vl_type_MountResult,
                &vl_type_MountRuntime,
                &vl_type_PathType,
                &vl_type_PathSpec,
                &vl_type_PathContext,
                &vl_type_PathResult,
                &vl_type_PathRuntime,
                &vl_type_OOMPolicy,
                &vl_type_ScopeContext,
                &vl_type_ScopeResult,
                &vl_type_ScopeRuntime,
                &vl_type_SocketBindIPv6Only,
                &vl_type_SocketTimestamping,
                &vl_type_SocketDeferTrigger,
                &vl_type_SocketListen,
                &vl_type_SocketContext,
                &vl_type_SocketResult,
                &vl_type_SocketRuntime,
                &vl_type_SwapContext,
                &vl_type_SwapResult,
                &vl_type_SwapRuntime,
                &vl_type_TimerBase,
                &vl_type_TimerSpec,
                &vl_type_TimerContext,
                &vl_type_TimerResult,
                &vl_type_TimerRuntime,

                /* UnitContext enums */
                &vl_type_CollectMode,
                &vl_type_EmergencyAction,

                /* Shared types (used by both StartTransient and Unit.List) */
                SD_VARLINK_SYMBOL_COMMENT("Service type"),
                &vl_type_ServiceType,
                SD_VARLINK_SYMBOL_COMMENT("Job mode"),
                &vl_type_JobMode,
                SD_VARLINK_SYMBOL_COMMENT("Job type (defined in io.systemd.Job)"),
                &vl_type_JobType,
                SD_VARLINK_SYMBOL_COMMENT("Job state (defined in io.systemd.Job)"),
                &vl_type_JobState,
                SD_VARLINK_SYMBOL_COMMENT("Job result (defined in io.systemd.Job)"),
                &vl_type_JobResult,
                SD_VARLINK_SYMBOL_COMMENT("A job object (defined in io.systemd.Job)"),
                &vl_type_Job,
                SD_VARLINK_SYMBOL_COMMENT("Service-specific context"),
                &vl_type_ServiceContext,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("No matching unit found"),
                &vl_error_NoSuchUnit,
                SD_VARLINK_SYMBOL_COMMENT("The unit is masked"),
                &vl_error_UnitMasked,
                SD_VARLINK_SYMBOL_COMMENT("Unit is in a fatal error state"),
                &vl_error_UnitError,
                SD_VARLINK_SYMBOL_COMMENT("The named property cannot be set (via SetProperties() or at creation time via StartTransient())"),
                &vl_error_PropertyNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("Job for the unit may only be enqueued by dependencies"),
                &vl_error_OnlyByDependency,
                SD_VARLINK_SYMBOL_COMMENT("A unit that requires D-Bus cannot be started as D-Bus is shutting down"),
                &vl_error_DBusShuttingDown,
                SD_VARLINK_SYMBOL_COMMENT("A unit with this name already exists"),
                &vl_error_UnitExists,
                SD_VARLINK_SYMBOL_COMMENT("This unit type does not support transient units"),
                &vl_error_UnitTypeNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("The unit file content contains invalid settings"),
                &vl_error_BadUnitSetting);
