/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-unit-util.h"
#include "extract-word.h"
#include "unit-def.h"
#include "strv.h"
#include "tests.h"

static sd_bus *arg_bus = NULL;
STATIC_DESTRUCTOR_REGISTER(arg_bus, sd_bus_unrefp);

static void test_transient_settings_one(UnitType type, const char* const* lines) {
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        int r;

        if (!arg_bus)
                return (void) log_tests_skipped("no bus connection");

        ASSERT_OK(sd_bus_message_new(arg_bus, &m, SD_BUS_MESSAGE_METHOD_CALL));

        STRV_FOREACH(s, lines) {
                const char *t = *s;
                int expect = 1;

                if (t[0] == '-') {
                        _cleanup_free_ char *code = NULL;
                        ASSERT_OK(extract_first_word(&t, &code, " ", 0));
                        ASSERT_OK(r = errno_from_name(code + 1));
                        expect = -r;
                }

                r = bus_append_unit_property_assignment(m, type, t);
                log_debug("%s → %d/%s", t, r, r < 0 ? ERRNO_NAME(r) : yes_no(r));
                ASSERT_EQ(r, expect);
        }
}

/* The tests data below is in a format intended to be easy to read and write:
 * Examples can be plain or prefixed with a negative numeric error code:
 * - unadorned examples must return 1 (success),
 * - otherwise, the function must return the given error.
 * Note that some functions leave the message in a broken state and subsequent
 * attempts to extend the message will return -ENXIO.
 */

TEST(cgroup_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "DevicePolicy=strict",
                        "DevicePolicy=auto",
                        "DevicePolicy=closed",

                        "Slice=system.slice",
                        "Slice=user-1000.slice",
                        "Slice=system-getty-this-is-a-very-long-long-slice.slice",
                        "Slice=",

                        "ManagedOOMSwap=auto",
                        "ManagedOOMSwap=kill",
                        "ManagedOOMSwap=",

                        "ManagedOOMMemoryPressure=auto",
                        "ManagedOOMMemoryPressure=kill",
                        "ManagedOOMMemoryPressure=",

                        "ManagedOOMPreference=none",
                        "ManagedOOMPreference=avoid",
                        "ManagedOOMPreference=omit",

                        "MemoryPressureWatch=auto",
                        "MemoryPressureWatch=off",
                        "MemoryPressureWatch=on",
                        "MemoryPressureWatch=skip",

                        "DelegateSubgroup=foo",
                        "DelegateSubgroup=bar.scope",
                        "DelegateSubgroup=",

                        "MemoryAccounting=true",
                        "-EINVAL MemoryAccounting=false ",
                        "-EINVAL MemoryAccounting=    yes",
                        "-EINVAL MemoryAccounting=\t\tno\t\t",
                        "MemoryAccounting=1",
                        "MemoryAccounting=0",
                        "MemoryAccounting=on",
                        "MemoryAccounting=off",
                        "MemoryAccounting=True",
                        "MemoryAccounting=FALSE",
                        "MemoryAccounting=YES",
                        "MemoryAccounting=No",

                        "MemoryZSwapWriteback=true",
                        "MemoryZSwapWriteback=false",
                        "IOAccounting=yes",
                        "IOAccounting=no",
                        "TasksAccounting=1",
                        "TasksAccounting=0",
                        "IPAccounting=on",
                        "IPAccounting=off",
                        "CoredumpReceive=true",
                        "CoredumpReceive=false",

                        "CPUWeight=100",
                        "StartupCPUWeight=100",
                        "IOWeight=100",
                        "StartupIOWeight=100",

                        "AllowedCPUs=0-3",
                        "AllowedCPUs=1,3,5,7",
                        "StartupAllowedCPUs=0-1",
                        "StartupAllowedCPUs=2,4,6",

                        "AllowedMemoryNodes=0",
                        "AllowedMemoryNodes=0-2",
                        "AllowedMemoryNodes=0-2 3 5 7 3 2 1",
                        "StartupAllowedMemoryNodes=0",
                        "StartupAllowedMemoryNodes=1-3",

                        "DisableControllers=cpu",
                        "DisableControllers=    "
                        " cpu cpuacct cpuset io blkio memory devices pids bpf-firewall bpf-devices     "
                        " cpu cpuacct cpuset io blkio memory\tdevices\tpids\tbpf-firewall\tbpf-devices    ",

                        "Delegate=yes",

                        "MemoryMin=100M",
                        "DefaultMemoryLow=50M",
                        "DefaultMemoryMin=10M",
                        "MemoryLow=2T",
                        "MemoryHigh=4G",
                        "MemoryMax=2G",
                        "MemoryMax=infinity",
                        "MemorySwapMax=1G",
                        "MemorySwapMax=0",
                        "MemoryZSwapMax=500M",
                        "MemoryZSwapMax=1G",
                        "TasksMax=1000",
                        "TasksMax=infinity",

                        "CPUQuota=1%",
                        "CPUQuota=200%",
                        "CPUQuotaPeriodSec=100ms",
                        "CPUQuotaPeriodSec=1s",
                        "-ERANGE CPUQuota=0%",

                        "DeviceAllow=/dev/null rw",
                        "DeviceAllow=/dev/zero r",

                        "IODeviceWeight=/dev/sda 200",
                        "IODeviceWeight=/dev/nvme0n1 500",
                        "IODeviceLatencyTargetSec=/dev/sda 100ms",
                        "IODeviceLatencyTargetSec=/dev/nvme0n1 10ms",

                        "IPAddressAllow=10.0.0.0/8",
                        "IPAddressAllow=192.168.1.0/24 ::1",
                        "IPAddressDeny=0.0.0.0/0",
                        "IPAddressDeny=192.168.100.0/24",

                        "IPIngressFilterPath=/etc/systemd/bpf/ingress.bpf",
                        "IPEgressFilterPath=/etc/systemd/bpf/egress.bpf",

                        "BPFProgram=/usr/lib/systemd/bpf/custom.bpf",

                        "SocketBindAllow=tcp:80",
                        "SocketBindAllow=udp:53",
                        "SocketBindDeny=tcp:1-1023",
                        "SocketBindDeny=udp:9999-9999",
                        "SocketBindDeny=any",

                        "MemoryPressureThresholdSec=1s",
                        "MemoryPressureThresholdSec=1 min 5s 23ms",

                        "NFTSet=cgroup:inet:filter:my_service user:inet:filter:serviceuser",

                        "ManagedOOMMemoryPressureDurationSec=30s",
                        "ManagedOOMMemoryPressureDurationSec=infinity",
                        "ManagedOOMMemoryPressureLimit=0%",
                        "ManagedOOMMemoryPressureLimit=95.8%",
                        "ManagedOOMMemoryPressureLimit=95.88%",
                        "-EINVAL ManagedOOMMemoryPressureLimit=95.888%", /* too many digits after dot */
                        "ManagedOOMMemoryPressureLimit=100%",

                        "IOReadBandwidthMax=/dev/sda 1M",
                        "IOReadBandwidthMax=/dev/sdb 2000K",
                        "IOReadBandwidthMax=/dev/nvme0n1 100M",
                        "IOReadBandwidthMax=/dev/nvme0n1p1 1G",
                        "IOReadBandwidthMax=/dev/mapper/root infinity",
                        "IOWriteBandwidthMax=/dev/sda 1M",
                        "IOWriteBandwidthMax=/dev/sdb 2M",
                        "IOWriteBandwidthMax=/dev/nvme0n1 100M",
                        "IOWriteBandwidthMax=/dev/mapper/home infinity",

                        /* Various strange cases */
                        "DevicePolicy=",
                        "DevicePolicy=value=with=equals",
                        "DevicePolicy=auto domain",
                        "DevicePolicy=policy with spaces",
                        "Slice=complex-name_with.various-chars123",
                        "ManagedOOMSwap=kill immediate",
                        "ManagedOOMMemoryPressureLimit=50.5%",
                        "IOReadBandwidthMax=/dev/disk/by-uuid/12345678-1234-1234-1234-123456789012 100M",
                        "IOWriteBandwidthMax=/dev/disk/by-label/DATA 200M",
                        "IOReadBandwidthMax=/dev/disk/by-partlabel/EFI\\x20System\\x20Partition 500M",
                        "IOWriteBandwidthMax=/dev/disk/by-id/dm-uuid-CRYPT-LUKS2-00f7541884c34bff92f60faec9d8f217-luks-00f75418-84c3-4bff-92f6-0faec9d8f217 500M",
                        "DelegateSubgroup=very.long.subgroup.name.with.dots",
                        "MemoryPressureWatch=custom-value",

                        /* Properties with special characters and edge cases */
                        "Slice=user-$(id -u).slice",
                        "DelegateSubgroup=test@service.scope",
                        "DevicePolicy=auto,strict",
                        "ManagedOOMSwap=auto;kill",

                        /* Deprecated */
                        "MemoryLimit=1G",
                        "MemoryLimit=infinity",
                        "MemoryLimit=",
                        "CPUShares=1024",
                        "StartupCPUShares=1024",
                        "BlockIOAccounting=true",
                        "BlockIOWeight=100",
                        "StartupBlockIOWeight=1000",
                        "BlockIODeviceWeight=/dev/sda 500",
                        "BlockIOReadBandwidth=/dev/sda 1M",
                        "BlockIOWriteBandwidth=/dev/sda 1M",
                        "CPUAccounting=true"
        );

        test_transient_settings_one(UNIT_SERVICE, lines);
        /* Also UNIT_SOCKET, UNIT_SLICE, UNIT_SCOPE, UNIT_MOUNT. */
}

TEST(automount_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "Where=/mnt/data",
                        "Where=/home/user/./../storage",
                        "Where=non/absolute/path", // TODO: should this be allowed?

                        "ExtraOptions=uid=1000,gid=1000",
                        "ExtraOptions=    rw,noatime,user_xattr   ",

                        "DirectoryMode=0755",
                        "DirectoryMode=700",

                        "TimeoutIdleSec=60s",
                        "TimeoutIdleSec=1week 1 day 2h 3 minutes 300s 50 ms"
        );

        test_transient_settings_one(UNIT_AUTOMOUNT, lines);
}

TEST(execute_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        /* String properties */
                        "User=myuser",
                        "Group=mygroup",
                        "UtmpIdentifier=myservice",
                        "UtmpMode=init",
                        "UtmpMode=login",
                        "PAMName=login",
                        "PAMName=system-auth",
                        "TTYPath=/dev/tty1",
                        "TTYPath=/dev/pts/0",
                        "WorkingDirectory=/var/lib/myapp",
                        "RootDirectory=/srv/container",
                        "SyslogIdentifier=myservice",
                        "ProtectSystem=strict",
                        "ProtectSystem=true",
                        "ProtectSystem=false",
                        "ProtectHome=true",
                        "ProtectHome=read-only",
                        "ProtectHome=tmpfs",
                        "PrivateTmp=true",
                        "PrivateTmp=fAlSe",
                        "PrivateTmpEx=0001",
                        "PrivateTmpEx=0000",
                        "PrivateTmp=asdf",
                        "PrivateTmpEx=asdf",
                        "PrivateUsers=no",
                        "PrivateUsers=1",
                        "PrivateUsersEx=true",
                        "PrivateUsersEx=false",
                        "PrivateUsers=whatever",
                        "ProtectControlGroupsEx=true",
                        "ProtectControlGroupsEx=false",

                        "SELinuxContext=system_u:system_r:httpd_t:s0",
                        "RootImage=/var/lib/machines/container.raw",
                        "RootVerity=/var/lib/machines/container.verity",
                        "RuntimeDirectoryPreserve=true",
                        "RuntimeDirectoryPreserve=restart",
                        "Personality=x86-64",
                        "Personality=x86",
                        "KeyringMode=inherit",
                        "KeyringMode=private",
                        "KeyringMode=shared",
                        "ProtectProc=invisible",
                        "ProtectProc=noaccess",
                        "ProtectProc=ptraceable",
                        "ProcSubset=pid",
                        "ProcSubset=all",
                        "NetworkNamespacePath=/proc/123/ns/net",
                        "IPCNamespacePath=/proc/123/ns/ipc",
                        "LogNamespace=myapp",
                        "RootImagePolicy=closed",
                        "RootImagePolicy=strict",
                        "MountImagePolicy=closed",
                        "MountImagePolicy=strict",
                        "ExtensionImagePolicy=closed",
                        "ExtensionImagePolicy=strict",

                        /* PrivatePIDs is boolean, but a string. */
                        "PrivatePIDs=true",
                        "PrivatePIDs=false",
                        "PrivatePIDs=foooooooooo",

                        /* Boolean properties */
                        "IgnoreSIGPIPE=true",
                        "TTYVHangup=true",
                        "TTYReset=true",
                        "TTYVTDisallocate=true",
                        "PrivateDevices=true",
                        "PrivateNetwork=true",
                        "PrivateMounts=true",
                        "PrivateIPC=true",
                        "NoNewPrivileges=true",
                        "SyslogLevelPrefix=true",
                        "MemoryDenyWriteExecute=true",
                        "RestrictRealtime=true",
                        "DynamicUser=true",
                        "RemoveIPC=true",
                        "ProtectKernelTunables=true",
                        "ProtectKernelModules=true",
                        "ProtectKernelLogs=true",
                        "ProtectClock=true",
                        "ProtectControlGroups=true",
                        "MountAPIVFS=true",
                        "BindLogSockets=true",
                        "CPUSchedulingResetOnFork=true",
                        "LockPersonality=true",
                        "MemoryKSM=true",
                        "RestrictSUIDSGID=true",
                        "RootEphemeral=true",
                        "SetLoginEnvironment=true",

                        /* Path and directory strvs */
                        "ReadWriteDirectories=/var/lib/myapp",
                        "ReadWriteDirectories=/var/lib/myapp /tmp/workdir",
                        "ReadOnlyDirectories=/usr/share/data",
                        "ReadOnlyDirectories=/usr/share/data /etc/config",
                        "InaccessibleDirectories=/home /root",
                        "ReadWritePaths=/var/lib/myapp /tmp/workdir",
                        "ReadOnlyPaths=",
                        "ReadOnlyPaths=/ /./ /../../ /usr/share/data /etc/config",
                        "InaccessiblePaths=/home",
                        "InaccessiblePaths=/home /root /var/cache",
                        "ExecPaths=/usr/bin /usr/local/bin",
                        "NoExecPaths=/tmp /var/tmp",
                        "ExecSearchPath=/usr/bin:/usr/local/bin",
                        "ExtensionDirectories=/var/lib/extensions /opt/extensions",
                        "ConfigurationDirectory=myapp subdir",
                        "SupplementaryGroups=wheel audio video",
                        "SystemCallArchitectures=native x86-64",

                        /* Log levels and facilities */
                        "SyslogLevel=info",
                        "SyslogLevel=debug",
                        "SyslogLevel=warning",
                        "SyslogLevel=err",
                        "-EINVAL SyslogLevel=error",
                        "LogLevelMax=info",
                        "LogLevelMax=debug",
                        "LogLevelMax=warning",
                        "SyslogFacility=daemon",
                        "SyslogFacility=local0",
                        "SyslogFacility=mail",

                        /* Various */
                        "SecureBits=keep-caps",
                        "SecureBits=keep-caps-locked",
                        "SecureBits=no-setuid-fixup",

                        "CPUSchedulingPolicy=other",
                        "CPUSchedulingPolicy=fifo",
                        "CPUSchedulingPolicy=rr",
                        "CPUSchedulingPriority=50",
                        "CPUSchedulingPriority=1",
                        "CPUSchedulingPriority=99",
                        "-ERANGE CPUSchedulingPriority=2147483648",

                        "OOMScoreAdjust=100",
                        "OOMScoreAdjust=-100",
                        "OOMScoreAdjust=0",
                        "CoredumpFilter=0x33",
                        "CoredumpFilter=0x7f",
                        "Nice=10",
                        "Nice=-10",
                        "SystemCallErrorNumber=EPERM",
                        "SystemCallErrorNumber=EACCES",
                        "SystemCallErrorNumber=kill",

                        "IOSchedulingClass=1",
                        "IOSchedulingPriority=4",

                        "RuntimeDirectoryMode=0755",
                        "RuntimeDirectoryMode=750",
                        "StateDirectoryMode=0000",
                        "CacheDirectoryMode=0755",
                        "LogsDirectoryMode=0755",
                        "ConfigurationDirectoryMode=0755",
                        "UMask=0002",

                        "TimerSlackNSec=50ms",
                        "LogRateLimitIntervalSec=30s",
                        "LogRateLimitBurst=1000",

                        "TTYRows=24",
                        "TTYColumns=80",

                        "MountFlags=shared",
                        "MountFlags=slave",
                        "MountFlags=private",

                        "Environment=PATH=/usr/bin:/bin",
                        "Environment=HOME=/home/user USER=myuser",
                        "UnsetEnvironment=TEMP",
                        "UnsetEnvironment=TEMP TMP",
                        "PassEnvironment=PATH",
                        "PassEnvironment=PATH HOME USER",
                        "EnvironmentFile=/etc/default/myservice",
                        "EnvironmentFile=-/etc/default/myservice",

                        "SetCredential=username:nonsecret",
                        "SetCredential=token1:abcdef123456 token2: token3:asdf:asdf",
                        "SetCredential=",
                        /* "-EPIPE SetCredentialEncrypted=password:encrypted_data token:encrypted_too", */

                        "LoadCredential=",
                        "LoadCredential=asdf",
                        "LoadCredential=cert:/etc/ssl/cert.pem",
                        "LoadCredential=key:/etc/ssl/key.pem",
                        "LoadCredentialEncrypted=password:encrypted_file",
                        "ImportCredential=*",
                        "ImportCredential=prefix.*",
                        "ImportCredentialEx=*",
                        "ImportCredentialEx=prefix.*",

                        "LogExtraFields=FIELD1=value1",
                        "LogExtraFields=FIELD1=value1 FIELD2=value2",
                        "LogFilterPatterns=~debug",
                        "LogFilterPatterns=~debug ~trace",

                        "StandardInput=null",
                        "StandardInput=tty",
                        "StandardInput=socket",
                        "StandardOutput=journal",
                        "StandardOutput=syslog",
                        "StandardOutput=null",
                        "StandardError=journal",
                        "StandardError=syslog",
                        "StandardError=null",
                        "StandardInputText=Hello World",
                        "StandardInputText=Multi\nLine\nText",
                        "StandardInputData=SGVsbG8gV29ybGQ=",

                        "AppArmorProfile=myprofile",
                        "AppArmorProfile=unconfined",
                        "SmackProcessLabel=mylabel",
                        "SmackProcessLabel=_",

                        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
                        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE CAP_SYS_TIME",
                        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
                        "AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SYS_TIME",

                        "CPUAffinity=0-3",
                        "CPUAffinity=0,2,4,6",
                        "CPUAffinity=1",

                        "NUMAPolicy=default",
                        "NUMAPolicy=preferred",
                        "NUMAPolicy=bind",
                        "NUMAMask=0-3",
                        "NUMAMask=0,2,4,6",

                        "RestrictAddressFamilies=AF_INET",
                        "RestrictAddressFamilies=AF_INET AF_INET6",
                        "RestrictAddressFamilies=~AF_NETLINK",
                        "RestrictFileSystems=ext4",
                        "RestrictFileSystems=ext4 xfs",
                        "RestrictFileSystems=~tmpfs",
                        "SystemCallFilter=@system-service",
                        "SystemCallFilter=read write open close",
                        "SystemCallFilter=~@debug",
                        "SystemCallLog=@system-service",
                        "SystemCallLog=read write open",
                        "RestrictNetworkInterfaces=lo",
                        "RestrictNetworkInterfaces=lo eth0",
                        "RestrictNetworkInterfaces=~wlan0",
                        "RestrictNamespaces=cgroup",
                        "RestrictNamespaces=cgroup ipc net",
                        "RestrictNamespaces=~user",
                        "DelegateNamespaces=pid",
                        "DelegateNamespaces=pid net",

                        "BindPaths=/host/path:/container/path",
                        "BindPaths=/host/path:/container/path:rbind",
                        "BindReadOnlyPaths=/host/ro:/container/ro",
                        "BindReadOnlyPaths=/host/ro:/container/ro:rbind",

                        "TemporaryFileSystem=/tmp",
                        "TemporaryFileSystem=/tmp:rw,nodev,nosuid,size=100M /with/colons/in/options:rw,size=10%:::::::: \"/with/spaces path/:option1:option2\"",
                        /* "-EINVAL TemporaryFileSystem=\"/tmp path", */
                        "TemporaryFileSystem=",

                        "RootHash=/a/path",
                        "RootHash=1234567890abcdef1234567890abcdef",
                        "RootHashSignature=/a/path",
                        "RootHashSignature=base64:zKFyIq7aZn4EpuCCmpcF9jPgD8JFE1g/xfT0Mas8X4M0WycyigRsQ4IH4yysufus0AORQsuk3oeGhRC7t1tLyKD0Ih0VcYedv5+p8e6itqrIwzecu98+rNyUVDhWBzS0PMwxEw==",

                        "RootImageOptions=partition=root,rw",
                        "RootImageOptions=partition=usr,ro",
                        "MountImages=/path/to/image.raw:/mount/point",
                        "MountImages=/path/to/image.raw:/mount/point:partition=1",
                        "ExtensionImages=/path/to/ext.raw",
                        "ExtensionImages=/path/to/ext.raw:/opt/extension",

                        "StateDirectory=myapp",
                        "StateDirectory=myapp subdir",
                        "RuntimeDirectory=myapp",
                        "RuntimeDirectory=myapp subdir",
                        "CacheDirectory=myapp",
                        "CacheDirectory=myapp subdir",
                        "LogsDirectory=myapp",
                        "LogsDirectory=myapp subdir",

                        "ProtectHostname=true",
                        "ProtectHostname=false",
                        "ProtectHostname=private",
                        "ProtectHostnameEx=true",
                        "ProtectHostnameEx=false",
                        "ProtectHostnameEx=private",
                        "ProtectHostname=true:foo",
                        "ProtectHostname=false:foo",
                        "ProtectHostname=private:foo",
                        "ProtectHostnameEx=true:foo",
                        "ProtectHostnameEx=false:foo",
                        "ProtectHostnameEx=private:foo",
                        "ProtectHostname=private:a.b.c.d.example.org",

                        "LimitCPU=15",
                        "LimitCPU=15:35",
                        "LimitCPU=infinity",
                        "LimitFSIZE=123",
                        "LimitDATA=1",
                        "LimitSTACK=1:2",
                        "LimitCORE=0",
                        "LimitRSS=0",
                        "LimitNPROC=0",
                        "LimitNOFILE=1234",
                        "LimitMEMLOCK=infinity",
                        "LimitAS=44",
                        "LimitLOCKS=22",
                        "LimitSIGPENDING=11",
                        "LimitMSGQUEUE=0",
                        "LimitNICE=0",
                        "LimitRTPRIO=0",
                        "LimitRTTIME=0"
        );

        test_transient_settings_one(UNIT_SOCKET, lines);
        /* Also UNIT_SERVICE, UNIT_MOUNT. */
}

TEST(kill_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "KillMode=control-group",
                        "KillMode=process",
                        "KillMode=mixed",
                        "KillMode=none",

                        "SendSIGHUP=true",
                        "SendSIGKILL=true",

                        "KillSignal=1",
                        "KillSignal=64",  /* _NSIG == 64 */
                        "-ERANGE KillSignal=0",
                        "-ERANGE KillSignal=65",
                        "RestartKillSignal=TERM",
                        "RestartKillSignal=SIGTERM",
                        "FinalKillSignal=WINCH",
                        "FinalKillSignal=SIGWINCH",
                        "FinalKillSignal=2",
                        "WatchdogSignal=RTMIN",
                        "WatchdogSignal=RTMIN+0"
        );

        test_transient_settings_one(UNIT_SCOPE, lines);
        /* Also UNIT_SERVICE, UNIT_SOCKET, UNIT_MOUNT. */
}

TEST(mount_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "What=/dev/sda1",
                        "What=UUID=12345678-1234-1234-1234-123456789012",

                        "Where=/mnt/disk",
                        "Where=non/absolute/var/lib/data", // TODO: should this be allowed?

                        "Options=defaults",
                        "Options=   rw,noatime,user_xattr,acl more   ",
                        "Options=",

                        "Type=ext4",
                        "TimeoutSec= 90 s ",
                        "DirectoryMode=0755",
                        "SloppyOptions=true",
                        "LazyUnmount=true",
                        "ForceUnmount=true",
                        "ReadwriteOnly=true"
        );

        test_transient_settings_one(UNIT_MOUNT, lines);
}

TEST(path_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "MakeDirectory=true",
                        "DirectoryMode=0",
                        "DirectoryMode=1",

                        "PathExists=/var/lib/myapp/ready",
                        "PathExists=/tmp/../././././././././.../.../.../.../.../.../lockfile",

                        "PathExistsGlob=/var/log/*.log",
                        "PathExistsGlob=/home/*/Desktop???",

                        "PathChanged=/etc/myapp.conf",
                        "PathModified=/etc/passwd",
                        "DirectoryNotEmpty=/var/spool/mail",
                        "TriggerLimitBurst=10",
                        "PollLimitBurst=100",
                        "TriggerLimitIntervalSec=2s",
                        "PollLimitIntervalSec=5s"
        );

        test_transient_settings_one(UNIT_PATH, lines);
}

TEST(scope_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "RuntimeMaxSec=3600s",
                        "RuntimeRandomizedExtraSec=60s",
                        "TimeoutStopSec=90s",
                        "OOMPolicy=stop",
                        "OOMPolicy=continue",
                        "User=_some_user",
                        "User=1000",
                        "Group=mygroup",
                        "Group=users"
        );

        test_transient_settings_one(UNIT_SCOPE, lines);
}

TEST(service_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        /* String properties — no validity checking */
                        "PIDFile=/var/run/myservice.pid",
                        "PIDFile=/run/myservice.pid",
                        "PIDFile=/tmp/daemon.pid",
                        "Type=simple",
                        "Type=forking",
                        "Type=oneshot",
                        "Type=dbus",
                        "Type=notify",
                        "Type=idle",
                        "Type=exec",
                        "Type=   asdf    ",
                        "ExitType=main",
                        "ExitType=cgroup",
                        "Restart=no",
                        "Restart=on-success",
                        "Restart=on-failure",
                        "Restart=on-abnormal",
                        "Restart=on-watchdog",
                        "Restart=on-abort",
                        "Restart=always",
                        "RestartMode=normal",
                        "RestartMode=direct",
                        "BusName=org.example.MyService",
                        "BusName=com.company.daemon",
                        "BusName=net.domain.service",
                        "NotifyAccess=none",
                        "NotifyAccess=main",
                        "NotifyAccess=exec",
                        "NotifyAccess=all",
                        "USBFunctionDescriptors=/dev/usb-ffs/myfunction",
                        "USBFunctionStrings=/dev/usb-ffs/myfunction",
                        "OOMPolicy=stop",
                        "OOMPolicy=continue",
                        "OOMPolicy=kill",
                        "TimeoutStartFailureMode=terminate",
                        "TimeoutStartFailureMode=abort",
                        "TimeoutStartFailureMode=kill",
                        "TimeoutStopFailureMode=terminate",
                        "TimeoutStopFailureMode=abort",
                        "TimeoutStopFailureMode=kill",
                        "FileDescriptorStorePreserve=no",
                        "FileDescriptorStorePreserve=yes",
                        "FileDescriptorStorePreserve=restart",

                        /* Boolean properties */
                        "PermissionsStartOnly=true",
                        "RootDirectoryStartOnly=true",
                        "RemainAfterExit=true",
                        "GuessMainPID=true",
                        "-EINVAL GuessMainPID=WAT",

                        /* Timespan properties */
                        "RestartSec=5s",
                        "RestartSec=1 y 2 months 30s",
                        "RestartMaxDelaySec=5min",
                        "TimeoutStartSec=infinity",
                        "TimeoutStopSec=infinity",
                        "TimeoutAbortSec=0",
                        "RuntimeMaxSec=24h",
                        "RuntimeRandomizedExtraSec=30s",
                        "WatchdogSec=30s",
                        "TimeoutSec=90s",

                        /* Unsigned integer values */
                        "FileDescriptorStoreMax=0",
                        "FileDescriptorStoreMax=9999999",
                        "RestartSteps=10",

                        /* Exec command properties */
                        "ExecCondition=test -f /etc/myservice.conf",
                        "ExecStartPre=/usr/bin/mkdir -p /var/lib/myservice",
                        "ExecStartPre=-/usr/bin/systemctl is-active network.target",
                        "ExecStartPre=@/usr/bin/systemctl is-active network.target",
                        "ExecStartPre=:systemctl is-active network.target",
                        "ExecStartPre=+systemctl is-active network.target",
                        "ExecStartPre=!systemctl is-active network.target",
                        "ExecStartPre=|systemctl is-active network.target",
                        "ExecStartPre=!!true",
                        "ExecStart=@:+!|foobar bar bar",
                        "ExecStart=@:+!!|foobar bar bar",
                        "ExecStartPost=post post"
                        "ExecConditionEx=/usr/bin/test -f /etc/myservice.conf",
                        "ExecStartPreEx=/usr/bin/mkdir -p /var/lib/myservice",
                        "ExecStartEx=/usr/bin/myservice --config /etc/myservice.conf",
                        "ExecStartPostEx=/usr/bin/logger 'Service started'",
                        "ExecReload=/bin/kill -HUP $MAINPID",
                        "ExecStop=kill -TERM $MAINPID",
                        "ExecStopPost=+logger 'Service stopped'",
                        "ExecStopPost=rm -f /var/lib/myservice/started",
                        "ExecReloadEx=/bin/kill -HUP $MAINPID",
                        "ExecStopEx=/bin/kill -TERM $MAINPID",
                        "ExecStopPostEx=/usr/bin/logger 'Service stopped'",

                        "RestartPreventExitStatus=1",
                        "RestartPreventExitStatus=1 2 8 SIGTERM",
                        "RestartPreventExitStatus=SIGKILL SIGTERM",
                        "RestartForceExitStatus=1",
                        "RestartForceExitStatus=1 2 8 SIGTERM",
                        "RestartForceExitStatus=SIGKILL SIGTERM",
                        "SuccessExitStatus=0",
                        "SuccessExitStatus=0 1 2",
                        "SuccessExitStatus=0 SIGTERM SIGKILL",

                        "OpenFile=/a/path",
                        "OpenFile=/etc/myservice.conf:SOME$NAME",
                        "OpenFile=/etc/myservice.conf:SOME$NAME:read-only",
                        "OpenFile=/etc/myservice.conf:SOME$NAME:append",
                        "OpenFile=/etc/myservice.conf:SOME$NAME:truncate",
                        "OpenFile=/etc/myservice.conf:SOME$NAME:graceful",
                        "OpenFile=/etc/myservice.conf::read-only,graceful",
                        "OpenFile=/etc/myservice.conf::truncate,graceful",
                        "-EINVAL OpenFile=/etc/myservice.conf::append,truncate,read-only,graceful",

                        "ReloadSignal=RTMAX",
                        "ReloadSignal=RTMAX-0",
                        "ReloadSignal=RTMAX-5",
                        "-ERANGE ReloadSignal=RTMAX-100"
        );

        test_transient_settings_one(UNIT_SERVICE, lines);
}

TEST(socket_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        /* Boolean properties */
                        "Accept=true",
                        "FlushPending=true",
                        "Writable=true",
                        "KeepAlive=true",
                        "NoDelay=true",
                        "FreeBind=true",
                        "Transparent=true",
                        "Broadcast=true",
                        "PassCredentials=true",
                        "PassFileDescriptorsToExec=true",
                        "PassSecurity=true",
                        "PassPacketInfo=true",
                        "ReusePort=true",
                        "RemoveOnStop=true",
                        "SELinuxContextFromNet=true",

                        /* Integer properties */
                        "Priority=6",
                        "Priority=0000000",
                        "Priority=-1",
                        "IPTTL=64",
                        "IPTTL=255",
                        "IPTTL=1",
                        "Mark=1",
                        "Mark=0",
                        "Mark=255",

                        /* IP TOS properties */
                        "IPTOS=0",
                        "IPTOS=low-delay",
                        "IPTOS=throughput",
                        "IPTOS=reliability",
                        "IPTOS=low-cost",

                        /* Unsigned integer properties */
                        "Backlog=0",
                        "Backlog=128",
                        "MaxConnections=64",
                        "MaxConnectionsPerSource=10",
                        "KeepAliveProbes=9",
                        "TriggerLimitBurst=10",
                        "PollLimitBurst=10",

                        /* Mode properties */
                        "SocketMode=0666",
                        "SocketMode=644",
                        "DirectoryMode=0755",
                        "DirectoryMode=0",

                        /* 64-bit integer properties */
                        "MessageQueueMaxMessages=10",
                        "MessageQueueMessageSize=8192",

                        /* Timespan properties */
                        "TimeoutSec=90s",
                        "TimeoutSec=5min",
                        "TimeoutSec=infinity",
                        "KeepAliveTimeSec=7200s",
                        "KeepAliveTimeSec=2h",
                        "KeepAliveTimeSec=30min",
                        "KeepAliveIntervalSec=75s",
                        "KeepAliveIntervalSec=1min",
                        "KeepAliveIntervalSec=30s",
                        "DeferAcceptSec=1w",
                        "TriggerLimitIntervalSec=2s",
                        "PollLimitIntervalSec=2s",
                        "DeferTriggerMaxSec=infinity",

                        /* Size properties */
                        "ReceiveBuffer=262144",
                        "ReceiveBuffer=1M",
                        "ReceiveBuffer=512K",
                        "SendBuffer=1.M",  // TODO: should this accept multiple components?
                        "PipeSize=512K",

                        /* Exec command properties */
                        "ExecStartPre=true",
                        "ExecStartPost=false",
                        "ExecReload=kill",
                        "ExecStopPost=signal",

                        /* More string properties */
                        "SmackLabel=mylabel",
                        "SmackLabel=_",
                        "SmackLabelIPIn=mylabel",
                        "SmackLabelIPIn=_",
                        "SmackLabelIPOut=mylabel",
                        "SmackLabelIPOut=_",
                        "TCPCongestion=cubic",
                        "TCPCongestion=reno",
                        "TCPCongestion=bbr",
                        "BindToDevice=eth0",
                        "BindToDevice=wlan0",
                        "BindToDevice=lo",
                        "BindIPv6Only=default",
                        "BindIPv6Only=both",
                        "BindIPv6Only=ipv6-only",
                        "FileDescriptorName=myfd",
                        "FileDescriptorName=socket",
                        "FileDescriptorName=listener",
                        "SocketUser=myuser",
                        "SocketUser=www-data",
                        "SocketGroup=mygroup",
                        "SocketGroup=www-data",
                        "Timestamping=off",
                        "Timestamping=us",
                        "Timestamping=ns",
                        "DeferTrigger=on",
                        "DeferTrigger=off",
                        "DeferTrigger=all",

                        /* Path strv */
                        "Symlinks=/var/lib/socket/link",
                        "Symlinks=/var/lib/socket/link /tmp/socket-link non/abs/path",

                        /* Socket protocol properties */
                        "SocketProtocol=udp",
                        "SocketProtocol=tcp",
                        "SocketProtocol=sctp",

                        /* Listen* properties */
                        "ListenStream=8080",
                        "ListenStream=127.0.0.1:8080",
                        "ListenStream=[::1]:8080",
                        "ListenStream=/run/myservice.sock",
                        "ListenDatagram=8080",
                        "ListenDatagram=127.0.0.1:8080",
                        "ListenDatagram=[::1]:8080",
                        "ListenDatagram=/run/myservice.sock",
                        "ListenSequentialPacket=/run/myservice.sock",
                        "ListenSequentialPacket=/tmp/socket",
                        "ListenNetlink=kobject-uevent",
                        "ListenNetlink=audit",
                        "ListenNetlink=route",
                        "ListenSpecial=/dev/log",
                        "ListenSpecial=/dev/kmsg",
                        "ListenSpecial=/proc/kmsg",
                        "ListenMessageQueue=/myqueue",
                        "ListenMessageQueue=/system/queue",
                        "ListenFIFO=/var/lib/myservice/fifo",
                        "ListenFIFO=/tmp/myfifo",
                        "ListenUSBFunction=/dev/usb-ffs/myfunction"
        );
        test_transient_settings_one(UNIT_SOCKET, lines);
}

TEST(timer_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "WakeSystem=true",
                        "RemainAfterElapse=yes",
                        "Persistent=true",
                        "OnTimezoneChange=yes",
                        "OnClockChange=true",
                        "FixedRandomDelay=yes",
                        "DeferReactivation=true",

                        "AccuracySec=1s",
                        "AccuracySec=10min",
                        "AccuracySec=1h",
                        "RandomizedDelaySec=30s",
                        "RandomizedDelaySec=5min",
                        "RandomizedDelaySec=0",
                        "RandomizedOffsetSec=15s",
                        "RandomizedOffsetSec=2min",
                        "OnActiveSec=10s",
                        "OnActiveSec=5min",
                        "OnBootSec=30s",
                        "OnBootSec=2min",
                        "OnStartupSec=45s",
                        "OnStartupSec=1min",
                        "OnUnitActiveSec=20s",
                        "OnUnitActiveSec=10min",
                        "OnUnitInactiveSec=60s",
                        "OnUnitInactiveSec=30min",
                        "OnCalendar=daily",
                        "OnCalendar=Mon,Tue *-*-* 12:00:00",
                        "OnCalendar=*-*-* 06:00:00",
                        "OnCalendar=Sat *-*-* 23:00:00"
        );

        test_transient_settings_one(UNIT_TIMER, lines);
}

TEST(unit_properties) {
        const char* const *lines = STRV_MAKE_CONST(
                        "Description=My Service Unit",
                        "SourcePath=/etc/systemd/system/myservice.service",
                        "SourcePath=non/abs/lib/systemd/system/backup.service",
                        "OnFailureJobMode=replace",
                        "OnFailureJobMode=fail",
                        "OnFailureJobMode=isolate",
                        "JobTimeoutAction=none",
                        "JobTimeoutAction=reboot",
                        "JobTimeoutAction=poweroff",
                        "JobTimeoutRebootArgument=emergency",
                        "JobTimeoutRebootArgument=--force",
                        "StartLimitAction=none",
                        "StartLimitAction=reboot",
                        "StartLimitAction=reboot-force",
                        "FailureAction=none",
                        "FailureAction=restart",
                        "FailureAction=reboot",
                        "SuccessAction=none",
                        "SuccessAction=poweroff",
                        "SuccessAction=exit",
                        "RebootArgument=--force",
                        "RebootArgument=emergency",
                        "CollectMode=inactive",
                        "CollectMode=inactive-or-failed",
                        "StopWhenUnneeded=true",
                        "StopWhenUnneeded=false",
                        "RefuseManualStart=yes",
                        "RefuseManualStart=no",
                        "RefuseManualStop=true",
                        "RefuseManualStop=false",
                        "AllowIsolate=yes",
                        "AllowIsolate=no",
                        "IgnoreOnIsolate=true",
                        "IgnoreOnIsolate=false",
                        "SurviveFinalKillSignal=yes",
                        "SurviveFinalKillSignal=no",
                        "DefaultDependencies=true",
                        "DefaultDependencies=false",
                        "JobTimeoutSec=90s",
                        "JobTimeoutSec=5min",
                        "JobTimeoutSec=infinity",
                        "JobRunningTimeoutSec=30min",
                        "JobRunningTimeoutSec=1h",
                        "StartLimitIntervalSec=10s",
                        "StartLimitIntervalSec=60s",
                        "StartLimitBurst=5",
                        "StartLimitBurst=9999999",
                        "StartLimitBurst=0",
                        "SuccessActionExitStatus=0",
                        "SuccessActionExitStatus=",
                        "FailureActionExitStatus=1",
                        "FailureActionExitStatus=",
                        "Documentation=man:myservice(8)",
                        "Documentation=https://example.com/docs",
                        "Documentation=file:/usr/share/doc/myservice/README",
                        "RequiresMountsFor=/var/lib/myservice",
                        "RequiresMountsFor=\t\t\t   \t/home\t\t\t\t\t/var/log    \t",
                        "WantsMountsFor=/tmp",
                        "WantsMountsFor=/opt /usr/local",
                        "Markers=manual",
                        "Markers=needs-reload",
                        "Markers=manual needs-reload",


                        "Requires=a.service b.service",
                        "Requisite=a.service b.service",
                        "Wants=a.service b.service",
                        "BindsTo=a.service b.service",
                        "PartOf=a.service b.service",
                        "Upholds=a.service b.service",
                        "RequiredBy=a.service b.service",
                        "RequisiteOf=a.service b.service",
                        "WantedBy=a.service b.service",
                        "BoundBy=a.service b.service",
                        "ConsistsOf=a.service b.service",
                        "UpheldBy=a.service b.service",
                        "Conflicts=a.service b.service",
                        "ConflictedBy=a.service b.service",
                        "Before=a.service b.service",
                        "After=a.service b.service",
                        "OnSuccess=a.service b.service",
                        "OnSuccessOf=a.service b.service",
                        "OnFailure=a.service b.service",
                        "OnFailureOf=a.service b.service",
                        "Triggers=a.service b.service",
                        "TriggeredBy=a.service b.service",
                        "PropagatesReloadTo=a.service b.service",
                        "ReloadPropagatedFrom=a.service b.service",
                        "PropagatesStopTo=a.service b.service",
                        "StopPropagatedFrom=a.service b.service",
                        "JoinsNamespaceOf=a.service b.service",
                        "References=a.service b.service",
                        "ReferencedBy=a.service b.service",
                        "InSlice=a.service b.service",
                        "SliceOf=a.service b.service",

                        // TODO: do better verification here?
                        "ConditionArchitecture=aarch64",
                        "ConditionArchitecture=|!aarch64",
                        "ConditionArchitecture=!aarch64",
                        "ConditionArchitecture=|aarch64",
                        "ConditionArchitecture=|!",
                        "ConditionFirmware=something",
                        "ConditionVirtualization=|foo",
                        "ConditionHost=|foo",
                        "ConditionKernelCommandLine=|foo",
                        "ConditionVersion=|foo",
                        "ConditionCredential=|foo",
                        "ConditionSecurity=|foo",
                        "ConditionCapability=|foo",
                        "ConditionACPower=|foo",
                        "ConditionMemory=|foo",
                        "ConditionCPUs=|foo",
                        "ConditionEnvironment=|foo",
                        "ConditionCPUFeature=|foo",
                        "ConditionOSRelease=|foo",
                        "ConditionMemoryPressure=|foo",
                        "ConditionCPUPressure=|foo",
                        "ConditionIOPressure=|foo",
                        "ConditionNeedsUpdate=|foo",
                        "ConditionFirstBoot=|foo",
                        "ConditionPathExists=|foo",
                        "ConditionPathExistsGlob=|foo",
                        "ConditionPathIsDirectory=|foo",
                        "ConditionPathIsSymbolicLink=|foo",
                        "ConditionPathIsMountPoint=|foo",
                        "ConditionPathIsReadWrite=|foo",
                        "ConditionPathIsEncrypted=|foo",
                        "ConditionPathIsSocket=|foo",
                        "ConditionDirectoryNotEmpty=|foo",
                        "ConditionFileNotEmpty=|foo",
                        "ConditionFileIsExecutable=|foo",
                        "ConditionUser=|foo",
                        "ConditionGroup=|foo",
                        "ConditionControlGroupController=|foo",
                        "ConditionKernelModuleLoaded=|foo",
                        "AssertArchitecture=|foo",
                        "AssertFirmware=|foo",
                        "AssertVirtualization=|foo",
                        "AssertHost=|foo",
                        "AssertKernelCommandLine=|foo",
                        "AssertVersion=|foo",
                        "AssertCredential=|foo",
                        "AssertSecurity=|foo",
                        "AssertCapability=|foo",
                        "AssertACPower=|foo",
                        "AssertMemory=|foo",
                        "AssertCPUs=|foo",
                        "AssertEnvironment=|foo",
                        "AssertCPUFeature=|foo",
                        "AssertOSRelease=|foo",
                        "AssertMemoryPressure=|foo",
                        "AssertCPUPressure=|foo",
                        "AssertIOPressure=|foo",
                        "AssertNeedsUpdate=|foo",
                        "AssertFirstBoot=|foo",
                        "AssertPathExists=|foo",
                        "AssertPathExistsGlob=|foo",
                        "AssertPathIsDirectory=|foo",
                        "AssertPathIsSymbolicLink=|foo",
                        "AssertPathIsMountPoint=|foo",
                        "AssertPathIsReadWrite=|foo",
                        "AssertPathIsEncrypted=|foo",
                        "AssertPathIsSocket=|foo",
                        "AssertDirectoryNotEmpty=|foo",
                        "AssertFileNotEmpty=|foo",
                        "AssertFileIsExecutable=|foo",
                        "AssertUser=|foo",
                        "AssertGroup=|foo",
                        "AssertControlGroupController=|foo",
                        "AssertKernelModuleLoaded=|foo"
        );

        test_transient_settings_one(UNIT_TARGET, lines);
        /* All unit types. */
}

TEST(bus_dump_transient_settings) {
        for (UnitType t = 0; t < _UNIT_TYPE_MAX; t++) {
                log_info("==================== %s ====================", t < 0 ? "unit" : unit_type_to_string(t));
                bus_dump_transient_settings(t);
        }
}

static int intro(void) {
        int r;

        r = sd_bus_default_user(&arg_bus);
        if (r < 0)
                r = sd_bus_default_system(&arg_bus);
        if (r < 0)
                log_info_errno(r, "Failed to connect to bus: %m");

        return EXIT_SUCCESS;
}

DEFINE_TEST_MAIN_WITH_INTRO(LOG_DEBUG, intro);
