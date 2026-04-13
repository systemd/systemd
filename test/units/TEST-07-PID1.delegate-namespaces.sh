#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# IMPORTANT: For /proc/ to be remounted in pid namespace within an unprivileged user namespace, there needs to
# be at least 1 unmasked procfs mount in ANY directory. Otherwise, if /proc/ is masked (e.g. /proc/scsi is
# over-mounted with tmpfs), then mounting a new /proc/ will fail.
#
# Thus, to guarantee PrivatePIDs=yes tests for unprivileged users pass, we mount a new procfs on a temporary
# directory with no masking. This will guarantee an unprivileged user can mount a new /proc/ successfully.
mkdir -p /tmp/TEST-07-PID1-delegate-namespaces-proc
mount -t proc proc /tmp/TEST-07-PID1-delegate-namespaces-proc

at_exit() {
    umount /tmp/TEST-07-PID1-delegate-namespaces-proc
    rm -rf /tmp/TEST-07-PID1-delegate-namespaces-proc
}

trap at_exit EXIT

testcase_mount() {
    (! systemd-run -p PrivateUsersEx=self -p PrivateMounts=yes --wait --pipe -- mount --bind /usr /home)
    systemd-run -p PrivateUsersEx=self -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- mount --bind /usr /home
}

testcase_network() {
    (! systemd-run -p PrivateUsersEx=self -p PrivateNetwork=yes --wait --pipe -- ip link add veth1 type veth peer name veth2)
    systemd-run -p PrivateUsersEx=self -p PrivateNetwork=yes -p DelegateNamespaces=net --wait --pipe -- ip link add veth1 type veth peer name veth2
}

testcase_pid() {
    # MountAPIVFS=yes always bind mounts child mounts of APIVFS filesystems, which means /proc/sys is always read-only
    # so we can't write to it when running in a container.
    if ! systemd-detect-virt --container; then
        (! systemd-run -p PrivateUsersEx=self -p PrivatePIDs=yes -p MountAPIVFS=yes --wait --pipe -- bash -c 'echo 5 >/proc/sys/kernel/ns_last_pid')
        systemd-run -p PrivateUsersEx=self -p PrivatePIDs=yes -p MountAPIVFS=yes -p DelegateNamespaces=pid --wait --pipe -- bash -c 'echo 5 >/proc/sys/kernel/ns_last_pid'
    fi
}

testcase_uts() {
    (! systemd-run -p PrivateUsersEx=self -p ProtectHostname=private --wait --pipe -- hostname abc)
    systemd-run -p PrivateUsersEx=self -p ProtectHostname=private -p DelegateNamespaces=uts --wait --pipe -- hostname abc
}

testcase_implied_private_users_self() {
    # If not explicitly set PrivateUsers=self is implied.
    systemd-run -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- mount --bind /usr /home
    # If explicitly set it PrivateUsers= is not overridden.
    systemd-run -p PrivateUsersEx=identity -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- mount --bind /usr /home
    systemd-run -p PrivateUsersEx=identity -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0      65536"'
}

testcase_user_manager() {
    systemctl start user@0
    # DelegateNamespaces=yes is implied for user managers.
    systemd-run --machine=testuser@.host --user -p PrivateMounts=yes -p AmbientCapabilities="~" --wait --pipe -- mount --bind /usr /home
    # Even those with CAP_SYS_ADMIN.
    SYSTEMD_LOG_LEVEL=debug systemd-run --machine=.host --user -p PrivateMounts=yes --wait --pipe -- mount --bind /usr /home
    # But can be overridden for user managers that are running with CAP_SYS_ADMIN.
    (! systemd-run --machine=.host --user -p PrivateMounts=yes -p DelegateNamespaces=no --wait --pipe -- mount --bind /usr /home)
    # But not for those without CAP_SYS_ADMIN.
    systemd-run --machine=testuser@.host --user -p PrivateMounts=yes -p DelegateNamespaces=no -p AmbientCapabilities="~" --wait --pipe -- mount --bind /usr /home
}

testcase_multiple_features() {
    unsquashfs -force -no-xattrs -d /tmp/TEST-07-PID1-delegate-namespaces-root /usr/share/minimal_0.raw

    systemd-run \
        -p PrivatePIDs=yes \
        -p RootDirectory=/tmp/TEST-07-PID1-delegate-namespaces-root \
        -p ProcSubset=pid \
        -p BindReadOnlyPaths=/usr/share \
        -p NoNewPrivileges=yes \
        -p ProtectSystem=strict \
        -p User=testuser \
        -p Group=testuser \
        -p RuntimeDirectory=abc \
        -p StateDirectory=qed \
        -p InaccessiblePaths=/usr/include \
        -p TemporaryFileSystem=/home \
        -p PrivateTmp=yes \
        -p PrivateDevices=yes \
        -p PrivateNetwork=yes \
        -p PrivateUsers=self \
        -p PrivateIPC=yes \
        -p ProtectHostname=yes \
        -p ProtectClock=yes \
        -p ProtectKernelTunables=yes \
        -p ProtectKernelModules=yes \
        -p ProtectKernelLogs=yes \
        -p ProtectControlGroups=private \
        -p LockPersonality=yes \
        -p Environment=ABC=QED \
        -p DelegateNamespaces=yes \
        --wait \
        --pipe \
        grep MARKER=1 /etc/os-release

    rm -rf /tmp/TEST-07-PID1-delegate-namespaces-root
}

run_testcases
