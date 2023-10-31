#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

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
    systemd-run --wait --pipe -p ProtectSystem=yes \
        bash -xec "test ! -w /usr; test ! -w /boot; test -w /etc; test -w /var"
    systemd-run --wait --pipe -p ProtectSystem=full \
        bash -xec "test ! -w /usr; test ! -w /boot; test ! -w /etc; test -w /var"
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

    # Check if we correctly serialize, deserialize, and set directives that
    # have more complex internal handling
    #
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

    # io.latency not available by default on Debian stable
    if [ -e /sys/fs/cgroup/system.slice/io.latency ]; then
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

    losetup -d "$LODEV"
    rm -f "$TEMPFILE"
fi

systemd-run --wait --pipe -p BindPaths="/etc /home:/mnt:norbind -/foo/bar/baz:/usr:rbind" \
    bash -xec "mountpoint /etc; test -d /etc/systemd; mountpoint /mnt; ! mountpoint /usr"
systemd-run --wait --pipe -p BindReadOnlyPaths="/etc /home:/mnt:norbind -/foo/bar/baz:/usr:rbind" \
    bash -xec "test ! -w /etc; test ! -w /mnt; ! mountpoint /usr"

# Ensure that clean-up codepaths work correctly if activation ultimately fails
(! systemd-run --wait --pipe -p DynamicUser=yes -p WorkingDirectory=/nonexistent echo hello)
