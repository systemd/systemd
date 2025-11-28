#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

# Sanity checks
#
# We can't really test time, critical-chain and plot verbs here, as
# the testsuite service is a part of the boot transaction, so let's assume
# they fail
systemd-analyze || :
systemd-analyze time || :
systemd-analyze critical-chain || :
# blame
systemd-analyze blame
systemd-run --wait --user --pipe -M testuser@.host systemd-analyze blame --no-pager
(! systemd-analyze blame --global)
# plot
systemd-analyze plot >/dev/null || :
systemd-analyze plot --json=pretty >/dev/null || :
systemd-analyze plot --json=short >/dev/null || :
systemd-analyze plot --json=off >/dev/null || :
systemd-analyze plot --json=pretty --no-legend >/dev/null || :
systemd-analyze plot --json=short --no-legend >/dev/null || :
systemd-analyze plot --json=off --no-legend >/dev/null || :
systemd-analyze plot --table >/dev/null || :
systemd-analyze plot --table --no-legend >/dev/null || :
systemd-analyze plot --scale-svg=1.0 >/dev/null || :
systemd-analyze plot --scale-svg=1.0 --detailed >/dev/null || :
(! systemd-analyze plot --global)
# legacy/deprecated options (moved to systemctl, but still usable from analyze)
systemd-analyze log-level
systemd-analyze log-level "$(systemctl log-level)"
systemd-analyze get-log-level
systemd-analyze set-log-level "$(systemctl log-level)"
systemd-analyze log-target
systemd-analyze log-target "$(systemctl log-target)"
systemd-analyze get-log-target
systemd-analyze set-log-target "$(systemctl log-target)"
systemd-analyze service-watchdogs
systemd-analyze service-watchdogs "$(systemctl service-watchdogs)"
# dot
systemd-analyze dot >/dev/null
systemd-analyze dot systemd-journald.service >/dev/null
systemd-analyze dot systemd-journald.service systemd-logind.service >/dev/null
systemd-analyze dot --from-pattern="*" --from-pattern="*.service" systemd-journald.service >/dev/null
systemd-analyze dot --to-pattern="*" --to-pattern="*.service" systemd-journald.service >/dev/null
systemd-analyze dot --from-pattern="*.service" --to-pattern="*.service" systemd-journald.service >/dev/null
systemd-analyze dot --order systemd-journald.service systemd-logind.service >/dev/null
systemd-analyze dot --require systemd-journald.service systemd-logind.service >/dev/null
systemd-analyze dot "systemd-*.service" >/dev/null
(! systemd-analyze dot systemd-journald.service systemd-logind.service "*" bbb ccc)
(! systemd-analyze dot --global systemd-journald.service)
# dump
# this should be rate limited to 10 calls in 10 minutes for unprivileged callers
for _ in {1..10}; do
    runas testuser systemd-analyze dump systemd-journald.service >/dev/null
done
(! runas testuser systemd-analyze dump >/dev/null)
# still limited after a reload
systemctl daemon-reload
(! runas testuser systemd-analyze dump >/dev/null)
# and a re-exec
systemctl daemon-reexec
(! runas testuser systemd-analyze dump >/dev/null)
# privileged call, so should not be rate limited
for _ in {1..10}; do
    systemd-analyze dump systemd-journald.service >/dev/null
done
systemd-analyze dump >/dev/null
systemd-analyze dump "*" >/dev/null
systemd-analyze dump "*.socket" >/dev/null
systemd-analyze dump "*.socket" "*.service" aaaaaaa ... >/dev/null
systemd-analyze dump systemd-journald.service >/dev/null
(! systemd-analyze dump "")
(! systemd-analyze dump --global systemd-journald.service)
# malloc (supported only when built with glibc)
if built_with_musl; then
    (! systemd-analyze malloc)
else
    systemd-analyze malloc >/dev/null
fi
(! systemd-analyze malloc --global)
# unit-files
systemd-analyze unit-files >/dev/null
systemd-analyze unit-files systemd-journald.service >/dev/null
systemd-analyze unit-files "*" >/dev/null
systemd-analyze unit-files "*" aaaaaa "*.service" "*.target" >/dev/null
systemd-analyze unit-files --user >/dev/null
systemd-analyze unit-files --user "*" aaaaaa "*.service" "*.target" >/dev/null
(! systemd-analyze unit-files --global)
# unit-paths
systemd-analyze unit-paths
systemd-analyze unit-paths --user
systemd-analyze unit-paths --global
# exist-status
systemd-analyze exit-status
systemd-analyze exit-status STDOUT BPF
systemd-analyze exit-status 0 1 {63..65}
(! systemd-analyze exit-status STDOUT BPF "hello*")
(! systemd-analyze exit-status --global)
# capability
systemd-analyze capability
systemd-analyze capability cap_chown CAP_KILL
systemd-analyze capability 0 1 {30..32}
(! systemd-analyze capability cap_chown CAP_KILL "hello*")
(! systemd-analyze capability --global)
systemd-analyze capability -m 0000000000003c00
(! systemd-analyze capability -m 8000000000000000)
cap="$(systemd-analyze capability -m 0000000000003c00)"
[[ $cap != *cap_linux_immutable* ]]
[[ $cap == *cap_net_bind_service* ]]
[[ $cap == *cap_net_broadcast* ]]
[[ $cap == *cap_net_admin* ]]
[[ $cap == *cap_net_raw* ]]
[[ $cap != *cap_ipc_lock* ]]
# condition
mkdir -p /run/systemd/system
UNIT_NAME="analyze-condition-$RANDOM.service"
cat >"/run/systemd/system/$UNIT_NAME" <<EOF
[Unit]
AssertPathExists=/etc/os-release
AssertEnvironment=!FOOBAR
ConditionKernelVersion=>1.0
ConditionPathExists=/etc/os-release

[Service]
ExecStart=true
EOF
systemctl daemon-reload
systemd-analyze condition --unit="$UNIT_NAME"
systemd-analyze condition 'ConditionKernelVersion = ! <4.0' \
                          'ConditionKernelVersion = >=3.1' \
                          'ConditionACPower=|false' \
                          'ConditionArchitecture=|!arm' \
                          'AssertPathExists=/etc/os-release'
(! systemd-analyze condition 'ConditionArchitecture=|!arm' 'AssertXYZ=foo')
(! systemd-analyze condition 'ConditionKernelVersion=<1.0')
(! systemd-analyze condition 'AssertKernelVersion=<1.0')
(! systemd-analyze condition --global 'ConditionKernelVersion = ! <4.0')
# syscall-filter
systemd-analyze syscall-filter >/dev/null
systemd-analyze syscall-filter @chown @sync
systemd-analyze syscall-filter @sync @sync @sync
(! systemd-analyze syscall-filter @chown @sync @foobar)
(! systemd-analyze syscall-filter --global)
# filesystems (requires libbpf support)
if systemctl --version | grep "+BPF_FRAMEWORK"; then
    systemd-analyze filesystems >/dev/null
    systemd-analyze filesystems @basic-api
    systemd-analyze filesystems @basic-api @basic-api @basic-api
    (! systemd-analyze filesystems @basic-api @basic-api @foobar @basic-api)
    (! systemd-analyze filesystems --global @basic-api)
fi
# calendar
systemd-analyze calendar '*-2-29 0:0:0'
systemd-analyze calendar --iterations=5 '*-2-29 0:0:0'
systemd-analyze calendar '*-* *:*:*'
systemd-analyze calendar --iterations=5 '*-* *:*:*'
systemd-analyze calendar --iterations=50 '*-* *:*:*'
systemd-analyze calendar --iterations=0 '*-* *:*:*'
systemd-analyze calendar --iterations=5 '01-01-22 01:00:00'
systemd-analyze calendar --base-time=yesterday --iterations=5 '*-* *:*:*'
(! systemd-analyze calendar --iterations=0 '*-* 99:*:*')
(! systemd-analyze calendar --base-time=never '*-* *:*:*')
(! systemd-analyze calendar 1)
(! systemd-analyze calendar "")
(! systemd-analyze calendar --global '*-2-29 0:0:0')
# timestamp
systemd-analyze timestamp now
systemd-analyze timestamp -- -1
systemd-analyze timestamp yesterday now tomorrow
systemd-analyze timestamp 'Fri 2012-11-23 23:02:15'
systemd-analyze timestamp 'Fri 2012-11-23 23:02:15 UTC'
for i in $(timedatectl list-timezones); do
    [[ -e "/usr/share/zoneinfo/$i" ]] || continue
    systemd-analyze timestamp "Fri 2012-11-23 23:02:15 $i"
done
(! systemd-analyze timestamp yesterday never tomorrow)
(! systemd-analyze timestamp 1)
(! systemd-analyze timestamp '*-2-29 0:0:0')
(! systemd-analyze timestamp "")
(! systemd-analyze timestamp --global now)
# timespan
systemd-analyze timespan 1
systemd-analyze timespan 1s 300s '1year 0.000001s'
(! systemd-analyze timespan 1s 300s aaaaaa '1year 0.000001s')
(! systemd-analyze timespan -- -1)
(! systemd-analyze timespan '*-2-29 0:0:0')
(! systemd-analyze timespan "")
(! systemd-analyze timespan --global 1)
# cat-config
systemd-analyze cat-config systemd/system.conf >/dev/null
systemd-analyze cat-config /etc/systemd/system.conf >/dev/null
systemd-analyze cat-config systemd/system.conf systemd/journald.conf >/dev/null
systemd-analyze cat-config systemd/system.conf foo/bar systemd/journald.conf >/dev/null
systemd-analyze cat-config foo/bar
systemd-analyze cat-config --tldr systemd/system.conf >/dev/null
systemd-analyze cat-config --tldr /etc/systemd/system.conf >/dev/null
systemd-analyze cat-config --tldr systemd/system.conf systemd/journald.conf >/dev/null
systemd-analyze cat-config --tldr systemd/system.conf foo/bar systemd/journald.conf >/dev/null
systemd-analyze cat-config --tldr foo/bar
mkdir -p /run/test-analyze-cat-config/main.conf.d
cat >/run/test-analyze-cat-config/main.conf <<EOF
#  This file is part of systemd.
#
#  systemd is free software; you can redistribute it and/or modify it under the
#  terms of the GNU Lesser General Public License as published by the Free
#  Software Foundation; either version 2.1 of the License, or (at your option)
#  any later version.
#
# Entries in this file show the compile time defaults. Local configuration
# should be created by either modifying this file (or a copy of it placed in
# /etc/ if the original file is shipped in /usr/), or by creating "drop-ins" in
# the /etc/systemd/networkd.conf.d/ directory. The latter is generally
# recommended. Defaults can be restored by simply deleting the main
# configuration file and all drop-ins located in /etc/.
#
# Use 'systemd-analyze cat-config systemd/networkd.conf' to display the full config.
#
# See networkd.conf(5) for details.

[Network]
#SpeedMeter=no
#SpeedMeterIntervalSec=10sec
#ManageForeignRoutingPolicyRules=yes
#ManageForeignRoutes=yes
#ManageForeignNextHops=yes
#RouteTable=
#IPv4Forwarding=
#IPv6Forwarding=
#IPv6PrivacyExtensions=no
#UseDomains=no

#[IPv6AddressLabel]
#Prefix=
#Label=

[IPv6AcceptRA]
#UseDomains=

[DHCPv4]
ClientIdentifier=duid
#DUIDType=vendor
#DUIDRawData=
#UseDomains=

[DHCPv6]
#DUIDType=vendor
#DUIDRawData=
#UseDomains=

[DHCPServer]
PersistLeases=yes
EOF
cat >/run/test-analyze-cat-config/main.conf.d/override.conf <<EOF
[DHCPServer]
PersistLeases=no

[Network]
[Network]
[Network]
SpeedMeter=yes

Continuation=foo \\
             bar \\
# comment
             hogehoge \\
             \\
             aaa \\


             bbb
AAAA=bbbb
EOF
diff -u <(echo '# /run/test-analyze-cat-config/main.conf'
          cat /run/test-analyze-cat-config/main.conf
          echo
          echo '# /run/test-analyze-cat-config/main.conf.d/override.conf'
          cat /run/test-analyze-cat-config/main.conf.d/override.conf) \
         <(systemd-analyze cat-config test-analyze-cat-config/main.conf)
diff -u - <<EOF <(systemd-analyze --tldr cat-config test-analyze-cat-config/main.conf)
# /run/test-analyze-cat-config/main.conf
[DHCPv4]
ClientIdentifier=duid
[DHCPServer]
PersistLeases=yes

# /run/test-analyze-cat-config/main.conf.d/override.conf
[DHCPServer]
PersistLeases=no
[Network]
SpeedMeter=yes
Continuation=foo \\
             bar \\
             hogehoge \\
             aaa \\
             bbb
AAAA=bbbb
EOF
rm -rf /run/test-analyze-cat-config
(! systemd-analyze cat-config --global systemd/system.conf)
# security
systemd-analyze security
systemd-analyze security --json=off
systemd-analyze security --json=pretty | jq
systemd-analyze security --json=short | jq
(! systemd-analyze security --global)

if [[ ! -v ASAN_OPTIONS ]]; then
    # check that systemd-analyze cat-config paths work in a chroot
    mkdir -p /tmp/root
    mount --bind / /tmp/root
    mount -t proc proc /tmp/root/proc
    if mountpoint -q /usr; then
        mount --bind /usr /tmp/root/usr
    fi
    systemd-analyze cat-config systemd/system-preset >/tmp/out1
    chroot /tmp/root systemd-analyze cat-config systemd/system-preset >/tmp/out2
    diff /tmp/out{1,2}
fi

# verify
mkdir -p /tmp/img/usr/lib/systemd/system/
mkdir -p /tmp/img/opt/

touch /tmp/img/opt/script0.sh
chmod +x /tmp/img/opt/script0.sh

cat <<EOF >/tmp/img/usr/lib/systemd/system/testfile.service
[Service]
ExecStart = /opt/script0.sh
EOF

set +e
# Default behaviour is to recurse through all dependencies when unit is loaded
(! systemd-analyze verify --root=/tmp/img/ testfile.service)

# As above, recurses through all dependencies when unit is loaded
(! systemd-analyze verify --recursive-errors=yes --root=/tmp/img/ testfile.service)

# Recurses through unit file and its direct dependencies when unit is loaded
(! systemd-analyze verify --recursive-errors=one --root=/tmp/img/ testfile.service)

set -e

# zero exit status since dependencies are ignored when unit is loaded
systemd-analyze verify --recursive-errors=no --root=/tmp/img/ testfile.service

rm /tmp/img/usr/lib/systemd/system/testfile.service

cat <<EOF >/tmp/testfile.service
[Unit]
foo = bar

[Service]
ExecStart = echo hello
EOF

cat <<EOF >/tmp/testfile2.service
[Unit]
Requires = testfile.service

[Service]
ExecStart = echo hello
EOF

# Zero exit status since no additional dependencies are recursively loaded when the unit file is loaded
systemd-analyze verify --recursive-errors=no /tmp/testfile2.service

set +e
# Non-zero exit status since all associated dependencies are recursively loaded when the unit file is loaded
(! systemd-analyze verify --recursive-errors=yes /tmp/testfile2.service)
set -e

rm /tmp/testfile.service
rm /tmp/testfile2.service

cat <<EOF >/tmp/sample.service
[Unit]
Description = A Sample Service

[Service]
ExecStart = echo hello
Slice=support.slice
EOF

# Zero exit status since no additional dependencies are recursively loaded when the unit file is loaded
systemd-analyze verify --recursive-errors=no /tmp/sample.service

cat <<EOF >/tmp/testfile.service
[Service]
ExecStart = echo hello
DeviceAllow=/dev/sda
EOF

# Prevent regression from #13380 and #20859 where we can't verify hidden files
cp /tmp/testfile.service /tmp/.testfile.service

systemd-analyze verify /tmp/.testfile.service

rm /tmp/.testfile.service

# Alias a unit file's name on disk (see #20061)
cp /tmp/testfile.service /tmp/testsrvc

(! systemd-analyze verify /tmp/testsrvc)

systemd-analyze verify /tmp/testsrvc:alias.service

# Zero exit status since the value used for comparison determine exposure to security threats is by default 100
systemd-analyze security --offline=true /tmp/testfile.service

#The overall exposure level assigned to the unit is greater than the set threshold
(! systemd-analyze security --threshold=90 --offline=true /tmp/testfile.service)

# Ensure we print the list of ACLs, see https://github.com/systemd/systemd/issues/23185
systemd-analyze security --offline=true /tmp/testfile.service | grep -q -F "/dev/sda"

# Make sure that running generators under systemd-analyze verify works.
# Note: sd-analyze spawns generators in a sandbox which makes gcov unhapy, so temporarily override
#       $GCOV_PREFIX to make it skip generating any coverage reports
GCOV_PREFIX=/tmp systemd-analyze verify --generators /tmp/testfile.service

rm /tmp/testfile.service

cat <<EOF >/tmp/img/usr/lib/systemd/system/testfile.service
[Service]
ExecStart = echo hello
PrivateNetwork = yes
PrivateDevices = yes
PrivateUsers = yes
EOF

# The new overall exposure level assigned to the unit is less than the set thresholds
# Verifies that the --offline= option works with --root=
systemd-analyze security --threshold=90 --offline=true --root=/tmp/img/ testfile.service

cat <<EOF >/tmp/foo@.service
[Service]
ExecStart=ls
EOF

cat <<EOF >/tmp/hoge@test.service
[Service]
ExecStart=ls
EOF

# issue #30357
pushd /tmp
systemd-analyze verify foo@bar.service
systemd-analyze verify foo@.service
systemd-analyze verify hoge@test.service
(! systemd-analyze verify hoge@nonexist.service)
(! systemd-analyze verify hoge@.service)
popd
pushd /
systemd-analyze verify tmp/foo@bar.service
systemd-analyze verify tmp/foo@.service
systemd-analyze verify tmp/hoge@test.service
(! systemd-analyze verify tmp/hoge@nonexist.service)
(! systemd-analyze verify tmp/hoge@.service)
popd
pushd /usr
systemd-analyze verify ../tmp/foo@bar.service
systemd-analyze verify ../tmp/foo@.service
systemd-analyze verify ../tmp/hoge@test.service
(! systemd-analyze verify ../tmp/hoge@nonexist.service)
(! systemd-analyze verify ../tmp/hoge@.service)
popd
systemd-analyze verify /tmp/foo@bar.service
systemd-analyze verify /tmp/foo@.service
systemd-analyze verify /tmp/hoge@test.service
(! systemd-analyze verify /tmp/hoge@nonexist.service)
(! systemd-analyze verify /tmp/hoge@.service)

# test that all commands are verified.
cat <<EOF >/tmp/multi-exec-start.service
[Service]
Type=oneshot
ExecStart=true
ExecStart=ls
EOF
systemd-analyze verify /tmp/multi-exec-start.service
echo 'ExecStart=command-should-not-exist' >>/tmp/multi-exec-start.service
(! systemd-analyze verify /tmp/multi-exec-start.service)

# Prevent regression from #20233 where systemd-analyze will return nonzero exit codes on warnings

# Unit file with warning "Unknown key name 'foo' in section 'Unit', ignoring"
cat <<EOF >/tmp/testwarnings.service
[Unit]
Foo=Bar

[Service]
ExecStart=echo hello
EOF

# yes/no/one should all return nonzero exit status for warnings in unit file
(! systemd-analyze verify --recursive-errors=yes /tmp/testwarnings.service)

(! systemd-analyze verify --recursive-errors=no /tmp/testwarnings.service)

(! systemd-analyze verify --recursive-errors=one /tmp/testwarnings.service)

# zero exit status since no errors and only warnings
systemd-analyze verify /tmp/testwarnings.service

rm /tmp/testwarnings.service

TESTDATA=/usr/lib/systemd/tests/testdata/TEST-65-ANALYZE.units
systemd-analyze verify "${TESTDATA}/loopy.service"
systemd-analyze verify "${TESTDATA}/loopy2.service"
systemd-analyze verify "${TESTDATA}/loopy3.service"
systemd-analyze verify "${TESTDATA}/loopy4.service"

# Added an additional "INVALID_ID" id to the .json to verify that nothing breaks when input is malformed
# The PrivateNetwork id description and weight was changed to verify that 'security' is actually reading in
# values from the .json file when required. The default weight for "PrivateNetwork" is 2500, and the new weight
# assigned to that id in the .json file is 6000. This increased weight means that when the "PrivateNetwork" key is
# set to 'yes' (as above in the case of testfile.service) in the content of the unit file, the overall exposure
# level for the unit file should decrease to account for that increased weight.
cat <<EOF >/tmp/testfile.json
{"UserOrDynamicUser":
    {"description_bad": "Service runs as root user",
    "weight": 0,
    "range": 10
    },
"SupplementaryGroups":
    {"description_good": "Service has no supplementary groups",
    "description_bad": "Service runs with supplementary groups",
    "description_na": "Service runs as root, option does not matter",
    "weight": 200,
    "range": 1
    },
"PrivateDevices":
    {"description_good": "Service has no access to hardware devices",
    "description_bad": "Service potentially has access to hardware devices",
    "weight": 1000,
    "range": 1
    },
"PrivateMounts":
    {"description_good": "Service cannot install system mounts",
    "description_bad": "Service may install system mounts",
    "weight": 1000,
    "range": 1
    },
"PrivateNetwork":
    {"description_good": "Service doesn't have access to the host's network",
    "description_bad": "Service has access to the host's network",
    "weight": 6000,
    "range": 1
    },
"PrivateTmp":
    {"description_good": "Service has no access to other software's temporary files",
    "description_bad": "Service has access to other software's temporary files",
    "weight": 1000,
    "range": 1
    },
"PrivateUsers":
    {"description_good": "Service does not have access to other users",
    "description_bad": "Service has access to other users",
    "weight": 1000,
    "range": 1
    },
"ProtectControlGroups":
    {"description_good": "Service cannot modify the control group file system",
    "description_bad": "Service may modify the control group file system",
    "weight": 1000,
    "range": 1
    },
"ProtectKernelModules":
    {"description_good": "Service cannot load or read kernel modules",
    "description_bad": "Service may load or read kernel modules",
    "weight": 1000,
    "range": 1
    },
"ProtectKernelTunables":
    {"description_good": "Service cannot alter kernel tunables (/proc/sys, …)",
    "description_bad": "Service may alter kernel tunables",
    "weight": 1000,
    "range": 1
    },
"ProtectKernelLogs":
    {"description_good": "Service cannot read from or write to the kernel log ring buffer",
    "description_bad": "Service may read from or write to the kernel log ring buffer",
    "weight": 1000,
    "range": 1
    },
"ProtectClock":
    {"description_good": "Service cannot write to the hardware clock or system clock",
    "description_bad": "Service may write to the hardware clock or system clock",
    "weight": 1000,
    "range": 1
    },
"ProtectHome":
    {"weight": 1000,
    "range": 10
    },
"ProtectHostname":
    {"description_good": "Service cannot change system host/domainname",
    "description_bad": "Service may change system host/domainname",
    "weight": 50,
    "range": 1
    },
"ProtectSystem":
    {"weight": 1000,
    "range": 10
    },
"RootDirectoryOrRootImage":
    {"description_good": "Service has its own root directory/image",
    "description_bad": "Service runs within the host's root directory",
    "weight": 200,
    "range": 1
    },
"LockPersonality":
    {"description_good": "Service cannot change ABI personality",
    "description_bad": "Service may change ABI personality",
    "weight": 100,
    "range": 1
    },
"MemoryDenyWriteExecute":
    {"description_good": "Service cannot create writable executable memory mappings",
    "description_bad": "Service may create writable executable memory mappings",
    "weight": 100,
    "range": 1
    },
"NoNewPrivileges":
    {"description_good": "Service processes cannot acquire new privileges",
    "description_bad": "Service processes may acquire new privileges",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_ADMIN":
    {"description_good": "Service has no administrator privileges",
    "description_bad": "Service has administrator privileges",
    "weight": 1500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SET_UID_GID_PCAP":
    {"description_good": "Service cannot change UID/GID identities/capabilities",
    "description_bad": "Service may change UID/GID identities/capabilities",
    "weight": 1500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_PTRACE":
    {"description_good": "Service has no ptrace() debugging abilities",
    "description_bad": "Service has ptrace() debugging abilities",
    "weight": 1500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_TIME":
    {"description_good": "Service processes cannot change the system clock",
    "description_bad": "Service processes may change the system clock",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_NET_ADMIN":
    {"description_good": "Service has no network configuration privileges",
    "description_bad": "Service has network configuration privileges",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_RAWIO":
    {"description_good": "Service has no raw I/O access",
    "description_bad": "Service has raw I/O access",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_MODULE":
    {"description_good": "Service cannot load kernel modules",
    "description_bad": "Service may load kernel modules",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_AUDIT":
    {"description_good": "Service has no audit subsystem access",
    "description_bad": "Service has audit subsystem access",
    "weight": 500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYSLOG":
    {"description_good": "Service has no access to kernel logging",
    "description_bad": "Service has access to kernel logging",
    "weight": 500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_NICE_RESOURCE":
    {"description_good": "Service has no privileges to change resource use parameters",
    "description_bad": "Service has privileges to change resource use parameters",
    "weight": 500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_MKNOD":
    {"description_good": "Service cannot create device nodes",
    "description_bad": "Service may create device nodes",
    "weight": 500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_CHOWN_FSETID_SETFCAP":
    {"description_good": "Service cannot change file ownership/access mode/capabilities",
    "description_bad": "Service may change file ownership/access mode/capabilities unrestricted",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_DAC_FOWNER_IPC_OWNER":
    {"description_good": "Service cannot override UNIX file/IPC permission checks",
    "description_bad": "Service may override UNIX file/IPC permission checks",
    "weight": 1000,
    "range": 1
    },
"CapabilityBoundingSet_CAP_KILL":
    {"description_good": "Service cannot send UNIX signals to arbitrary processes",
    "description_bad": "Service may send UNIX signals to arbitrary processes",
    "weight": 500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_NET_BIND_SERVICE_BROADCAST_RAW":
    {"description_good": "Service has no elevated networking privileges",
    "description_bad": "Service has elevated networking privileges",
    "weight": 500,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_BOOT":
    {"description_good": "Service cannot issue reboot()",
    "description_bad": "Service may issue reboot()",
    "weight": 100,
    "range": 1
    },
"CapabilityBoundingSet_CAP_MAC":
    {"description_good": "Service cannot adjust SMACK MAC",
    "description_bad": "Service may adjust SMACK MAC",
    "weight": 100,
    "range": 1
    },
"CapabilityBoundingSet_CAP_LINUX_IMMUTABLE":
    {"description_good": "Service cannot mark files immutable",
    "description_bad": "Service may mark files immutable",
    "weight": 75,
    "range": 1
    },
"CapabilityBoundingSet_CAP_IPC_LOCK":
    {"description_good": "Service cannot lock memory into RAM",
    "description_bad": "Service may lock memory into RAM",
    "weight": 50,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_CHROOT":
    {"description_good": "Service cannot issue chroot()",
    "description_bad": "Service may issue chroot()",
    "weight": 50,
    "range": 1
    },
"CapabilityBoundingSet_CAP_BLOCK_SUSPEND":
    {"description_good": "Service cannot establish wake locks",
    "description_bad": "Service may establish wake locks",
    "weight": 25,
    "range": 1
    },
"CapabilityBoundingSet_CAP_WAKE_ALARM":
    {"description_good": "Service cannot program timers that wake up the system",
    "description_bad": "Service may program timers that wake up the system",
    "weight": 25,
    "range": 1
    },
"CapabilityBoundingSet_CAP_LEASE":
    {"description_good": "Service cannot create file leases",
    "description_bad": "Service may create file leases",
    "weight": 25,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_TTY_CONFIG":
    {"description_good": "Service cannot issue vhangup()",
    "description_bad": "Service may issue vhangup()",
    "weight": 25,
    "range": 1
    },
"CapabilityBoundingSet_CAP_SYS_PACCT":
    {"description_good": "Service cannot use acct()",
    "description_bad": "Service may use acct()",
    "weight": 25,
    "range": 1
    },
"CapabilityBoundingSet_CAP_BPF":
    {"description_good": "Service may load BPF programs",
    "description_bad": "Service may not load BPF programs",
    "weight": 25,
    "range": 1
    },
"UMask":
    {"weight": 100,
    "range": 10
    },
"KeyringMode":
    {"description_good": "Service doesn't share key material with other services",
    "description_bad": "Service shares key material with other service",
    "weight": 1000,
    "range": 1
    },
"ProtectProc":
    {"description_good": "Service has restricted access to process tree(/proc hidepid=)",
    "description_bad": "Service has full access to process tree(/proc hidepid=)",
    "weight": 1000,
    "range": 3
    },
"ProcSubset":
    {"description_good": "Service has no access to non-process/proc files(/proc subset=)",
    "description_bad": "Service has full access to non-process/proc files(/proc subset=)",
    "weight": 10,
    "range": 1
    },
"NotifyAccess":
    {"description_good": "Service child processes cannot alter service state",
    "description_bad": "Service child processes may alter service state",
    "weight": 1000,
    "range": 1
    },
"RemoveIPC":
    {"description_good": "Service user cannot leave SysV IPC objects around",
    "description_bad": "Service user may leave SysV IPC objects around",
    "description_na": "Service runs as root, option does not apply",
    "weight": 100,
    "range": 1
    },
"Delegate":
    {"description_good": "Service does not maintain its own delegated control group subtree",
    "description_bad": "Service maintains its own delegated control group subtree",
    "weight": 100,
    "range": 1
    },
"RestrictRealtime":
    {"description_good": "Service realtime scheduling access is restricted",
    "description_bad": "Service may acquire realtime scheduling",
    "weight": 500,
    "range": 1
    },
"RestrictSUIDSGID":
    {"description_good": "SUID/SGIDfilecreationbyserviceisrestricted",
    "description_bad": "ServicemaycreateSUID/SGIDfiles",
    "weight": 1000,
    "range": 1
    },
"RestrictNamespaces_user":
    {"description_good": "Servicecannotcreateusernamespaces",
    "description_bad": "Servicemaycreateusernamespaces",
    "weight": 1500,
    "range": 1
    },
"RestrictNamespaces_mnt":
    {"description_good": "Service cannot create file system namespaces",
    "description_bad": "Service may create file system namespaces",
    "weight": 500,
    "range": 1
    },
"RestrictNamespaces_ipc":
    {"description_good": "Service cannot create IPC namespaces",
    "description_bad": "Service may create IPC namespaces",
    "weight": 500,
    "range": 1
    },
"RestrictNamespaces_pid":
    {"description_good": "Service cannot create process namespaces",
    "description_bad": "Service may create process namespaces",
    "weight": 500,
    "range": 1
    },
"RestrictNamespaces_cgroup":
    {"description_good": "Service cannot create cgroup namespaces",
    "description_bad": "Service may create cgroup namespaces",
    "weight": 500,
    "range": 1
    },
"RestrictNamespaces_net":
    {"description_good": "Service cannot create network namespaces",
    "description_bad": "Service may create network namespaces",
    "weight": 500,
    "range": 1
    },
"RestrictNamespaces_uts":
    {"description_good": "Service cannot create hostname namespaces",
    "description_bad": "Service may create hostname namespaces",
    "weight": 100,
    "range": 1
    },
"RestrictAddressFamilies_AF_INET_INET6":
    {"description_good": "Service cannot allocate Internet sockets",
    "description_bad": "Service may allocate Internet sockets",
    "weight": 1500,
    "range": 1
    },
"RestrictAddressFamilies_AF_UNIX":
    {"description_good": "Service cannot allocate local sockets",
    "description_bad": "Service may allocate local sockets",
    "weight": 25,
    "range": 1
    },
"RestrictAddressFamilies_AF_NETLINK":
    {"description_good": "Service cannot allocate netlink sockets",
    "description_bad": "Service may allocate netlink sockets",
    "weight": 200,
    "range": 1
    },
"RestrictAddressFamilies_AF_PACKET":
    {"description_good": "Service cannot allocate packet sockets",
    "description_bad": "Service may allocate packet sockets",
    "weight": 1000,
    "range": 1
    },
"RestrictAddressFamilies_OTHER":
    {"description_good": "Service cannot allocate exotic sockets",
    "description_bad": "Service may allocate exotic sockets",
    "weight": 1250,
    "range": 1
    },
"SystemCallArchitectures":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_swap":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_obsolete":
    {"weight": 250,
    "range": 10
    },
"SystemCallFilter_clock":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_cpu_emulation":
    {"weight": 250,
    "range": 10
    },
"SystemCallFilter_debug":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_mount":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_module":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_raw_io":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_reboot":
    {"weight": 1000,
    "range": 10
    },
"SystemCallFilter_privileged":
    {"weight": 700,
    "range": 10
    },
"SystemCallFilter_resources":
    {"weight": 700,
    "range": 10
    },
"IPAddressDeny":
    {"weight": 1000,
    "range": 10
    },
"DeviceAllow":
    {"weight": 1000,
    "range": 10
    },
"AmbientCapabilities":
    {"description_good": "Service process does not receive ambient capabilities",
    "description_bad": "Service process receives ambient capabilities",
    "weight": 500,
    "range": 1
    },
"INVALID_ID":
    {"weight": 1000,
    "range": 10
    }
}
EOF

# Reads in custom security requirements from the parsed .json file and uses these for comparison
systemd-analyze security --threshold=90 --offline=true \
                           --security-policy=/tmp/testfile.json \
                           --root=/tmp/img/ testfile.service

# The strict profile adds a lot of sandboxing options
systemd-analyze security --threshold=25 --offline=true \
                           --security-policy=/tmp/testfile.json \
                           --profile=strict \
                           --root=/tmp/img/ testfile.service

# The trusted profile doesn't add any sandboxing options
(! systemd-analyze security --threshold=25 --offline=true \
                           --security-policy=/tmp/testfile.json \
                           --profile=/usr/lib/systemd/portable/profile/trusted/service.conf \
                           --root=/tmp/img/ testfile.service)

(! systemd-analyze security --threshold=50 --offline=true \
                           --security-policy=/tmp/testfile.json \
                           --root=/tmp/img/ testfile.service)

rm /tmp/img/usr/lib/systemd/system/testfile.service

if systemd-analyze --version | grep -q -F "+ELFUTILS"; then
    systemd-analyze inspect-elf /lib/systemd/systemd
    systemd-analyze inspect-elf --json=short /lib/systemd/systemd | grep -q -F '"elfType":"executable"'

    # For some unknown reason the .note.dlopen sections are removed when building with sanitizers, so only
    # run this test if we're not running under sanitizers.
    if [[ ! -v ASAN_OPTIONS ]]; then
        shared="$(ldd /lib/systemd/systemd | grep shared | cut -d' ' -f3)"
        systemd-analyze dlopen-metadata "$shared"
        systemd-analyze dlopen-metadata --json=short "$shared"
    fi
fi

systemd-analyze --threshold=90 security systemd-journald.service

# issue 23663
check() {(
    set +x
    output=$(systemd-analyze security --offline="${2?}" "${3?}" | grep -F 'SystemCallFilter=')
    assert_in "System call ${1?} list" "$output"
    assert_in "[+✓] SystemCallFilter=~@swap" "$output"
    assert_in "[+✓] SystemCallFilter=~@resources" "$output"
    assert_in "[+✓] SystemCallFilter=~@reboot" "$output"
    assert_in "[+✓] SystemCallFilter=~@raw-io" "$output"
    assert_in "[-✗] SystemCallFilter=~@privileged" "$output"
    assert_in "[+✓] SystemCallFilter=~@obsolete" "$output"
    assert_in "[+✓] SystemCallFilter=~@mount" "$output"
    assert_in "[+✓] SystemCallFilter=~@module" "$output"
    assert_in "[+✓] SystemCallFilter=~@debug" "$output"
    assert_in "[+✓] SystemCallFilter=~@cpu-emulation" "$output"
    assert_in "[-✗] SystemCallFilter=~@clock" "$output"
)}

export -n SYSTEMD_LOG_LEVEL

mkdir -p /run/systemd/system
cat >/run/systemd/system/allow-list.service <<EOF
[Service]
ExecStart=false
SystemCallFilter=@system-service
SystemCallFilter=~@resources:ENOANO @privileged
SystemCallFilter=@clock
EOF

cat >/run/systemd/system/deny-list.service <<EOF
[Service]
ExecStart=false
SystemCallFilter=~@known
SystemCallFilter=@system-service
SystemCallFilter=~@resources:ENOANO @privileged
SystemCallFilter=@clock
EOF

systemctl daemon-reload

check allow yes /run/systemd/system/allow-list.service
check allow no allow-list.service
check deny yes /run/systemd/system/deny-list.service
check deny no deny-list.service

output=$(systemd-run -p "SystemCallFilter=@system-service" -p "SystemCallFilter=~@resources:ENOANO @privileged" -p "SystemCallFilter=@clock" sleep 60 2>&1)
name=$(echo "$output" | awk '{ print $4 }' | cut -d';' -f1)

check allow yes /run/systemd/transient/"$name"
check allow no "$name"

output=$(systemd-run -p "SystemCallFilter=~@known" -p "SystemCallFilter=@system-service" -p "SystemCallFilter=~@resources:ENOANO @privileged" -p "SystemCallFilter=@clock" sleep 60 2>&1)
name=$(echo "$output" | awk '{ print $4 }' | cut -d';' -f1)

check deny yes /run/systemd/transient/"$name"
check deny no "$name"

# Let's also test the "image-policy" verb

systemd-analyze image-policy '*' 2>&1 | grep -q -F "Long form: =verity+signed+encrypted+unprotected+unused+absent"
systemd-analyze image-policy '-' 2>&1 | grep -q -F "Long form: =unused+absent"
systemd-analyze image-policy 'home=encrypted:usr=verity' 2>&1 | grep -q -F "Long form: usr=verity:home=encrypted:=unused+absent"
systemd-analyze image-policy 'home=encrypted:usr=verity' 2>&1 | grep -q -e '^home \+encrypted \+'
systemd-analyze image-policy 'home=encrypted:usr=verity' 2>&1 | grep -q -e '^usr \+verity \+'
systemd-analyze image-policy 'home=encrypted:usr=verity' 2>&1 | grep -q -e '^root \+ignore \+'
systemd-analyze image-policy 'home=encrypted:usr=verity' 2>&1 | grep -q -e '^usr-verity \+unprotected \+'

(! systemd-analyze image-policy 'doedel')

# Output is very hard to predict, but let's run it for coverage anyway
systemd-analyze pcrs
systemd-analyze pcrs --json=pretty
systemd-analyze pcrs 14 7 0 ima
if systemd-analyze has-tpm2 -q ; then
    systemd-analyze nvpcrs
    systemd-analyze nvpcrs --json=pretty
    systemd-analyze nvpcrs hardware cryptsetup
fi

systemd-analyze architectures
systemd-analyze architectures --json=pretty
systemd-analyze architectures x86
systemd-analyze architectures x86-64
systemd-analyze architectures native
systemd-analyze architectures uname

systemd-analyze smbios11
systemd-analyze smbios11 -q

if test -f /sys/class/dmi/id/board_vendor && ! systemd-detect-virt --container ; then
    systemd-analyze chid
    systemd-analyze chid --json=pretty
fi

systemd-analyze condition --instance=tmp --unit=systemd-growfs@.service
systemd-analyze verify --instance=tmp --man=no systemd-growfs@.service
systemd-analyze security --instance=tmp systemd-growfs@.service

systemd-analyze has-tpm2 ||:
if systemd-analyze has-tpm2 -q ; then
    echo "have tpm2"
else
    echo "have no tpm2"
fi

# Test "transient-settings" verb

# shellcheck disable=SC2046
systemd-analyze --no-pager transient-settings $(systemctl --no-legend --no-pager -t help)
systemd-analyze transient-settings service | grep NoNewPrivileges
systemd-analyze transient-settings mount | grep CPUQuotaPeriodSec
# make sure deprecated names are not printed
(! systemd-analyze transient-settings service | grep CPUAccounting )
(! systemd-analyze transient-settings service | grep ConditionKernelVersion )
(! systemd-analyze transient-settings service | grep AssertKernelVersion )
(! systemd-analyze transient-settings service socket timer path slice scope mount automount | grep -E 'Ex$' )

# check systemd-analyze unit-shell with a namespaced unit
UNIT_NAME="test-unit-shell.service"
UNIT_FILE="/run/systemd/system/$UNIT_NAME"
cat >"$UNIT_FILE" <<EOF
[Unit]
Description=Test unit for systemd-analyze unit-shell
[Service]
Type=notify
NotifyAccess=all
ExecStart=sh -c "echo 'Hello from test unit' >/tmp/testfile; systemd-notify --ready; sleep infinity"
PrivateTmp=disconnected
EOF
# Start the service
systemctl start "$UNIT_NAME"
# Wait for the service to be active
systemctl is-active --quiet "$UNIT_NAME"
# Verify the service is active and has a MainPID
MAIN_PID=$(systemctl show -p MainPID --value "$UNIT_NAME")
[ "$MAIN_PID" -gt 0 ]
# Test systemd-analyze unit-shell with a command (cat /tmp/testfile)
OUTPUT=$(systemd-analyze unit-shell "$UNIT_NAME" cat /tmp/testfile)
assert_in "Hello from test unit" "$OUTPUT"

touch /testok
