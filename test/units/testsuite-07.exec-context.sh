#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Make sure the unit's exec context matches its configuration
# See: https://github.com/systemd/systemd/pull/29552

# Even though hidepid= was introduced in kernel 3.3, we support only
# the post 5.8 implementation that allows us to apply the option per-instance,
# instead of the whole namespace. To distinguish between these two implementations
# lets check if we can mount procfs with a named value (e.g. hidepid=off), since
# support for this was introduced in the same commit as the per-instance stuff
proc_supports_option() {
    local option="${1:?}"
    local proc_tmp ec

    proc_tmp="$(mktemp -d)"
    mount -t proc -o "$option" proc "$proc_tmp" && ec=0 || ec=$?
    mountpoint -q "$proc_tmp" && umount -q "$proc_tmp"
    rm -rf "$proc_tmp"

    return $ec
}

# In coverage builds we disable ProtectSystem= and ProtectHome= via a service.d
# dropin in /etc. This dropin has, unfortunately, higher priority than
# the transient stuff from systemd-run. Let's just skip the following tests
# in that case instead of complicating the test setup even more */
if [[ -z "${COVERAGE_BUILD_DIR:-}" ]]; then
    if ! systemd-detect-virt -cq && command -v bootctl >/dev/null; then
        boot_path="$(bootctl --print-boot-path)"
        esp_path="$(bootctl --print-esp-path)"

        # If the mount points are handled by automount units, make sure we trigger
        # them before proceeding further
        ls -l "$boot_path" "$esp_path"
    fi

    systemd-run --wait --pipe -p ProtectSystem=yes \
        bash -xec "test ! -w /usr; ${boot_path:+"test ! -w $boot_path; test ! -w $esp_path;"} test -w /etc; test -w /var"
    systemd-run --wait --pipe -p ProtectSystem=full \
        bash -xec "test ! -w /usr; ${boot_path:+"test ! -w $boot_path; test ! -w $esp_path;"} test ! -w /etc; test -w /var"
    systemd-run --wait --pipe -p ProtectSystem=strict \
        bash -xec "test ! -w /; test ! -w /etc; test ! -w /var; test -w /dev; test -w /proc"
    systemd-run --wait --pipe -p ProtectSystem=no \
        bash -xec "test -w /; test -w /etc; test -w /var; test -w /dev; test -w /proc"

    MARK="$(mktemp /root/.exec-context.XXX)"
    systemd-run --wait --pipe -p ProtectHome=yes \
        bash -xec "test ! -w /home; test ! -w /root; test ! -w /run/user; test ! -e $MARK"
    systemd-run --wait --pipe -p ProtectHome=read-only \
        bash -xec "test ! -w /home; test ! -w /root; test ! -w /run/user; test -e $MARK"
    systemd-run --wait --pipe -p ProtectHome=tmpfs \
        bash -xec "test -w /home; test -w /root; test -w /run/user; test ! -e $MARK"
    systemd-run --wait --pipe -p ProtectHome=no \
        bash -xec "test -w /home; test -w /root; test -w /run/user; test -e $MARK"
    rm -f "$MARK"
fi

if proc_supports_option "hidepid=off"; then
    systemd-run --wait --pipe -p ProtectProc=noaccess -p User=testuser \
        bash -xec 'test -e /proc/1; test ! -r /proc/1; test -r /proc/$$$$/comm'
    systemd-run --wait --pipe -p ProtectProc=invisible -p User=testuser \
        bash -xec 'test ! -e /proc/1; test -r /proc/$$$$/comm'
    systemd-run --wait --pipe -p ProtectProc=ptraceable -p User=testuser \
        bash -xec 'test ! -e /proc/1; test -r /proc/$$$$/comm'
    systemd-run --wait --pipe -p ProtectProc=ptraceable -p User=testuser -p AmbientCapabilities=CAP_SYS_PTRACE \
        bash -xec 'test -r /proc/1; test -r /proc/$$$$/comm'
    systemd-run --wait --pipe -p ProtectProc=default -p User=testuser \
        bash -xec 'test -r /proc/1; test -r /proc/$$$$/comm'
fi

if proc_supports_option "subset=pid"; then
    systemd-run --wait --pipe -p ProcSubset=pid -p User=testuser \
        bash -xec "test -r /proc/1/comm; test ! -e /proc/cpuinfo"
    systemd-run --wait --pipe -p ProcSubset=all -p User=testuser \
        bash -xec "test -r /proc/1/comm; test -r /proc/cpuinfo"
fi

if ! systemd-detect-virt -cq; then
    systemd-run --wait --pipe -p ProtectKernelLogs=yes -p User=testuser \
        bash -xec "test ! -r /dev/kmsg"
    systemd-run --wait --pipe -p ProtectKernelLogs=no -p User=testuser \
        bash -xec "test -r /dev/kmsg"
fi

systemd-run --wait --pipe -p BindPaths="/etc /home:/mnt:norbind -/foo/bar/baz:/usr:rbind" \
    bash -xec "mountpoint /etc; test -d /etc/systemd; mountpoint /mnt; ! mountpoint /usr"
systemd-run --wait --pipe -p BindReadOnlyPaths="/etc /home:/mnt:norbind -/foo/bar/baz:/usr:rbind" \
    bash -xec "test ! -w /etc; test ! -w /mnt; ! mountpoint /usr"
# Make sure we properly serialize/deserialize paths with spaces
# See: https://github.com/systemd/systemd/issues/30747
touch "/tmp/test file with spaces"
systemd-run --wait --pipe -p TemporaryFileSystem="/tmp" -p BindPaths="/etc /home:/mnt:norbind /tmp/test\ file\ with\ spaces" \
    bash -xec "mountpoint /etc; test -d /etc/systemd; mountpoint /mnt; stat '/tmp/test file with spaces'"
systemd-run --wait --pipe -p TemporaryFileSystem="/tmp" -p BindPaths="/etc /home:/mnt:norbind /tmp/test\ file\ with\ spaces:/tmp/destination\ wi\:th\ spaces" \
    bash -xec "mountpoint /etc; test -d /etc/systemd; mountpoint /mnt; stat '/tmp/destination wi:th spaces'"

# Check if we correctly serialize, deserialize, and set directives that
# have more complex internal handling
if ! systemd-detect-virt -cq; then
    # Funny detail: this originally used the underlying rootfs device, but that,
    # for some reason, caused "divide error" in kernel, followed by a kernel panic
    TEMPFILE="$(mktemp)"
    LODEV="$(losetup --show -f "$TEMPFILE")"
    ROOT_DEV_MAJ_MIN="$(lsblk -nro MAJ:MIN "$LODEV")"
    EXPECTED_IO_MAX="$ROOT_DEV_MAJ_MIN rbps=1000 wbps=1000000000000 riops=2000000000 wiops=4000"
    EXPECTED_IO_LATENCY="$ROOT_DEV_MAJ_MIN target=69000"
    SERVICE_NAME="test-io-directives-$RANDOM.service"
    CGROUP_PATH="/sys/fs/cgroup/system.slice/$SERVICE_NAME"

    # IO*=
    ARGUMENTS=(
        # Throw in a couple of invalid entries just to test things out
        -p IOReadBandwidthMax="/foo/bar 1M"
        -p IOReadBandwidthMax="/foo/baz 1M"
        -p IOReadBandwidthMax="$LODEV 1M"
        -p IOReadBandwidthMax="$LODEV 1K"
        -p IOWriteBandwidthMax="$LODEV 1G"
        -p IOWriteBandwidthMax="$LODEV 1T"
        -p IOReadIOPSMax="$LODEV 2G"
        -p IOWriteIOPSMax="$LODEV 4K"
        -p IODeviceLatencyTargetSec="$LODEV 666ms"
        -p IODeviceLatencyTargetSec="/foo/bar 69ms"
        -p IODeviceLatencyTargetSec="$LODEV 69ms"
        -p IOReadBandwidthMax="/foo/bar 1M"
        -p IOReadBandwidthMax="/foo/baz 1M"
        # TODO: IODeviceWeight= doesn't work on loop devices and virtual disks
        -p IODeviceWeight="$LODEV 999"
        -p IODeviceWeight="/foo/bar 999"
    )

    systemctl set-property system.slice IOAccounting=yes
    # io.latency not available by default on Debian stable
    if [[ -e /sys/fs/cgroup/system.slice/io.latency ]]; then
        systemd-run --wait --pipe --unit "$SERVICE_NAME" "${ARGUMENTS[@]}" \
            bash -xec "diff <(echo $EXPECTED_IO_MAX) $CGROUP_PATH/io.max; diff <(echo $EXPECTED_IO_LATENCY) $CGROUP_PATH/io.latency"
    fi

    # CPUScheduling=
    ARGUMENTS=(
        -p CPUSchedulingPolicy=rr   # ID: 2
        -p CPUSchedulingPolicy=fifo # ID: 1
        -p CPUSchedulingPriority=5  # Actual prio: 94 (99 - prio)
        -p CPUSchedulingPriority=10 # Actual prio: 89 (99 - prio)
    )

    systemd-run --wait --pipe --unit "$SERVICE_NAME" "${ARGUMENTS[@]}" \
        bash -xec 'grep -E "^policy\s*:\s*1$" /proc/self/sched; grep -E "^prio\s*:\s*89$" /proc/self/sched'

    # Device*=
    ARGUMENTS=(
        -p DevicePolicy=closed
        -p DevicePolicy=strict
        -p DeviceAllow="char-mem rm"  # Allow read & mknod for /dev/{null,zero,...}
        -p DeviceAllow="/dev/loop0 rw"
        -p DeviceAllow="/dev/loop0 w" # Allow write for /dev/loop0
        # Everything else should be disallowed per the strict policy
    )

    systemd-run --wait --pipe --unit "$SERVICE_NAME" "${ARGUMENTS[@]}" \
        bash -xec 'test -r /dev/null; test ! -w /dev/null; test ! -r /dev/loop0; test -w /dev/loop0; test ! -r /dev/tty; test ! -w /dev/tty'

    if ! systemctl --version | grep -qF -- "-BPF_FRAMEWORK"; then
        # SocketBind*=
        ARGUMENTS=(
            -p SocketBindAllow=
            -p SocketBindAllow=1234
            -p SocketBindAllow=ipv4:udp:any
            -p SocketBindAllow=ipv6:6666
            # Everything but the last assignment is superfluous, but it still exercises
            # the parsing machinery
            -p SocketBindDeny=
            -p SocketBindDeny=1111
            -p SocketBindDeny=ipv4:1111
            -p SocketBindDeny=ipv4:any
            -p SocketBindDeny=ipv4:tcp:any
            -p SocketBindDeny=ipv4:udp:10000-11000
            -p SocketBindDeny=ipv6:1111
            -p SocketBindDeny=any
        )

        # We should fail with EPERM when trying to bind to a socket not on the allow list
        # (nc exits with 2 in that case)
        systemd-run --wait -p SuccessExitStatus="1 2" --pipe "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -l 127.0.0.1 9999; exit 42'
        systemd-run --wait -p SuccessExitStatus="1 2" --pipe "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -l ::1 9999; exit 42'
        systemd-run --wait -p SuccessExitStatus="1 2" --pipe "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -6 -u -l ::1 9999; exit 42'
        systemd-run --wait -p SuccessExitStatus="1 2" --pipe "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -4 -l 127.0.0.1 6666; exit 42'
        # Consequently, we should succeed when binding to a socket on the allow list
        # and keep listening on it until we're killed by `timeout` (EC 124)
        systemd-run --wait --pipe -p SuccessExitStatus=124 "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -4 -l 127.0.0.1 1234; exit 1'
        systemd-run --wait --pipe -p SuccessExitStatus=124 "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -4 -u -l 127.0.0.1 5678; exit 1'
        systemd-run --wait --pipe -p SuccessExitStatus=124 "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -6 -l ::1 1234; exit 1'
        systemd-run --wait --pipe -p SuccessExitStatus=124 "${ARGUMENTS[@]}" \
            bash -xec 'timeout 1s nc -6 -l ::1 6666; exit 1'
    fi

    losetup -d "$LODEV"
    rm -f "$TEMPFILE"
fi

# {Cache,Configuration,Logs,Runtime,State}Directory=
ARGUMENTS=(
    -p CacheDirectory="foo/bar/baz also\ with\ spaces"
    -p CacheDirectory="foo"
    -p CacheDirectory="context"
    -p CacheDirectoryMode="0123"
    -p CacheDirectoryMode="0666"
    -p ConfigurationDirectory="context/foo also_context/bar context/nested/baz context/semi\:colon"
    -p ConfigurationDirectoryMode="0400"
    -p LogsDirectory="context/foo"
    -p LogsDirectory=""
    -p LogsDirectory="context/a/very/nested/logs/dir"
    -p RuntimeDirectory="context/with\ spaces"
    # Note: {Runtime,State,Cache,Logs}Directory= directives support the directory:symlink syntax, which
    #       requires an additional level of escaping for the colon character
    -p RuntimeDirectory="also_context:a\ symlink\ with\ \\\:\ col\\\:ons\ and\ \ spaces"
    -p RuntimeDirectoryPreserve=yes
    -p StateDirectory="context"
    -p StateDirectory="./././././././context context context"
    -p StateDirectoryMode="0000"
)

rm -rf /run/context
systemd-run --wait --pipe "${ARGUMENTS[@]}" \
    bash -xec '[[ $CACHE_DIRECTORY == "/var/cache/also with spaces:/var/cache/context:/var/cache/foo:/var/cache/foo/bar/baz" ]];
               [[ $(stat -c "%a" "${CACHE_DIRECTORY##*:}") == 666 ]]'
systemd-run --wait --pipe "${ARGUMENTS[@]}" \
    bash -xec '[[ $CONFIGURATION_DIRECTORY == /etc/also_context/bar:/etc/context/foo:/etc/context/nested/baz:/etc/context/semi:colon ]];
               [[ $(stat -c "%a" "${CONFIGURATION_DIRECTORY%%:*}") == 400 ]]'
systemd-run --wait --pipe "${ARGUMENTS[@]}" \
    bash -xec '[[ $LOGS_DIRECTORY == /var/log/context/a/very/nested/logs/dir:/var/log/context/foo ]];
               [[ $(stat -c "%a" "${LOGS_DIRECTORY##*:}") == 755 ]]'
systemd-run --wait --pipe "${ARGUMENTS[@]}" \
    bash -xec '[[ $RUNTIME_DIRECTORY == "/run/also_context:/run/context/with spaces" ]];
               [[ $(stat -c "%a" "${RUNTIME_DIRECTORY##*:}") == 755 ]];
               [[ $(stat -c "%a" "${RUNTIME_DIRECTORY%%:*}") == 755 ]]'
systemd-run --wait --pipe "${ARGUMENTS[@]}" \
    bash -xec '[[ $STATE_DIRECTORY == /var/lib/context ]]; [[ $(stat -c "%a" $STATE_DIRECTORY) == 0 ]]'
test -d "/run/context/with spaces"
test -s "/run/a symlink with : col:ons and  spaces"
rm -rf /var/{cache,lib,log}/context /etc/{also_,}context

# Limit*=
#
# Note: keep limits of LimitDATA= and LimitAS= unlimited, otherwise ASan (LSan)
# won't be able to mmap the shadow maps
ARGUMENTS=(
    -p LimitCPU=15
    -p LimitCPU=10:15         # ulimit -t
    -p LimitFSIZE=96G         # ulimit -f
    -p LimitDATA=8T:infinity
    -p LimitDATA=infinity     # ulimit -d
    -p LimitSTACK=8M          # ulimit -s
    -p LimitCORE=infinity
    -p LimitCORE=17M          # ulimit -c
    -p LimitRSS=27G           # ulimit -m
    -p LimitNOFILE=7:127      # ulimit -n
    -p LimitAS=infinity       # ulimit -v
    -p LimitNPROC=1
    -p LimitNPROC=64:infinity # ulimit -u
    -p LimitMEMLOCK=37M       # ulimit -l
    -p LimitLOCKS=19:1021     # ulimit -x
    -p LimitSIGPENDING=21     # ulimit -i
    -p LimitMSGQUEUE=666      # ulimit -q
    -p LimitNICE=4            # ulimit -e
    -p LimitRTPRIO=8          # ulimit -r
    -p LimitRTTIME=666666     # ulimit -R
)
# Do all the checks in one giant inline shell blob to avoid the overhead of spawning
# a new service for each check
#
# Note: ulimit shows storage-related values in 1024-byte increments*
# Note2: ulimit -R requires bash >= 5.1
#
# * in POSIX mode -c a -f options show values in 512-byte increments; let's hope
#   we never run in the POSIX mode
systemd-run --wait --pipe "${ARGUMENTS[@]}" \
    bash -xec 'KB=1; MB=$((KB * 1024)); GB=$((MB * 1024)); TB=$((GB * 1024));
               : CPU;        [[ $(ulimit -St) -eq 10 ]];           [[ $(ulimit -Ht) -eq 15 ]];
               : FSIZE;      [[ $(ulimit -Sf) -eq $((96 * GB)) ]]; [[ $(ulimit -Hf) -eq $((96 * GB)) ]];
               : DATA;       [[ $(ulimit -Sd) == unlimited  ]];    [[ $(ulimit -Hd) == unlimited ]];
               : STACK;      [[ $(ulimit -Ss) -eq $((8 * MB)) ]];  [[ $(ulimit -Hs) -eq $((8 * MB)) ]];
               : CORE;       [[ $(ulimit -Sc) -eq $((17 * MB)) ]]; [[ $(ulimit -Hc) -eq $((17 * MB)) ]];
               : RSS;        [[ $(ulimit -Sm) -eq $((27 * GB)) ]]; [[ $(ulimit -Hm) -eq $((27 * GB)) ]];
               : NOFILE;     [[ $(ulimit -Sn) -eq 7 ]];            [[ $(ulimit -Hn) -eq 127 ]];
               : AS;         [[ $(ulimit -Sv) == unlimited ]];     [[ $(ulimit -Hv) == unlimited ]];
               : NPROC;      [[ $(ulimit -Su) -eq 64 ]];           [[ $(ulimit -Hu) == unlimited ]];
               : MEMLOCK;    [[ $(ulimit -Sl) -eq $((37 * MB)) ]]; [[ $(ulimit -Hl) -eq $((37 * MB)) ]];
               : LOCKS;      [[ $(ulimit -Sx) -eq 19 ]];           [[ $(ulimit -Hx) -eq 1021 ]];
               : SIGPENDING; [[ $(ulimit -Si) -eq 21 ]];           [[ $(ulimit -Hi) -eq 21 ]];
               : MSGQUEUE;   [[ $(ulimit -Sq) -eq 666 ]];          [[ $(ulimit -Hq) -eq 666 ]];
               : NICE;       [[ $(ulimit -Se) -eq 4 ]];            [[ $(ulimit -He) -eq 4 ]];
               : RTPRIO;     [[ $(ulimit -Sr) -eq 8 ]];            [[ $(ulimit -Hr) -eq 8 ]];
               ulimit -R || exit 0;
               : RTTIME;     [[ $(ulimit -SR) -eq 666666 ]];       [[ $(ulimit -HR) -eq 666666 ]];'

# RestrictFileSystems=
#
# Note: running instrumented binaries requires at least /proc to be accessible, so let's
#       skip the test when we're running under sanitizers
#
# Note: $GCOV_ERROR_LOG is used during coverage runs to suppress errors when creating *.gcda files,
#       since gcov can't access the restricted filesystem (as expected)
if [[ ! -v ASAN_OPTIONS ]] && systemctl --version | grep "+BPF_FRAMEWORK" && kernel_supports_lsm bpf; then
    ROOTFS="$(df --output=fstype /usr/bin | sed --quiet 2p)"
    systemd-run --wait --pipe -p RestrictFileSystems="" ls /
    systemd-run --wait --pipe -p RestrictFileSystems="$ROOTFS foo bar" ls /
    (! systemd-run --wait --pipe -p RestrictFileSystems="$ROOTFS" ls /proc)
    (! systemd-run --wait --pipe -p GCOV_ERROR_LOG=/dev/null -p RestrictFileSystems="foo" ls /)
    systemd-run --wait --pipe -p RestrictFileSystems="$ROOTFS foo bar baz proc" ls /proc
    systemd-run --wait --pipe -p RestrictFileSystems="$ROOTFS @foo @basic-api" ls /proc
    systemd-run --wait --pipe -p RestrictFileSystems="$ROOTFS @foo @basic-api" ls /sys/fs/cgroup

    systemd-run --wait --pipe -p RestrictFileSystems="~" ls /
    systemd-run --wait --pipe -p RestrictFileSystems="~proc" ls /
    systemd-run --wait --pipe -p RestrictFileSystems="~@basic-api" ls /
    (! systemd-run --wait --pipe -p GCOV_ERROR_LOG=/dev/null -p RestrictFileSystems="~$ROOTFS" ls /)
    (! systemd-run --wait --pipe -p RestrictFileSystems="~proc" ls /proc)
    (! systemd-run --wait --pipe -p RestrictFileSystems="~@basic-api" ls /proc)
    (! systemd-run --wait --pipe -p RestrictFileSystems="~proc foo @bar @basic-api" ls /proc)
    (! systemd-run --wait --pipe -p RestrictFileSystems="~proc foo @bar @basic-api" ls /sys)
    systemd-run --wait --pipe -p RestrictFileSystems="~proc devtmpfs sysfs" ls /
    (! systemd-run --wait --pipe -p RestrictFileSystems="~proc devtmpfs sysfs" ls /proc)
    (! systemd-run --wait --pipe -p RestrictFileSystems="~proc devtmpfs sysfs" ls /dev)
    (! systemd-run --wait --pipe -p RestrictFileSystems="~proc devtmpfs sysfs" ls /sys)
fi

# Ensure that clean-up codepaths work correctly if activation ultimately fails
touch /run/not-a-directory
mkdir /tmp/root
touch /tmp/root/foo
chmod +x /tmp/root/foo
(! systemd-run --wait --pipe false)
(! systemd-run --wait --pipe --unit "test-dynamicuser-fail" -p DynamicUser=yes -p WorkingDirectory=/nonexistent true)
(! systemd-run --wait --pipe -p RuntimeDirectory=not-a-directory true)
(! systemd-run --wait --pipe -p RootDirectory=/tmp/root this-shouldnt-exist)
(! systemd-run --wait --pipe -p RootDirectory=/tmp/root /foo)
(! systemd-run --wait --pipe --service-type=oneshot -p ExecStartPre=-/foo/bar/baz -p ExecStart=-/foo/bar/baz -p RootDirectory=/tmp/root -- "- foo")
