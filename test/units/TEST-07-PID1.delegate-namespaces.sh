#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

testcase_mount() {
    (! systemd-run -p PrivateUsersEx=self -p PrivateMounts=yes --wait --pipe -- mount --bind /usr /home)
    systemd-run -p PrivateUsersEx=self -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- mount --bind /usr /home
}

testcase_network() {
    (! systemd-run -p PrivateUsersEx=self -p PrivateNetwork=yes --wait --pipe -- ip link add veth1 type veth peer name veth2)
    systemd-run -p PrivateUsersEx=self -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- ip link add veth1 type veth peer name veth2
}

testcase_cgroup() {
    (! systemd-run -p PrivateUsersEx=self -p ProtectControlGroupsEx=private --wait --pipe -- sh -c 'echo 0 >/sys/fs/cgroup/cgroup.pressure')
    systemd-run -p PrivateUsersEx=self -p ProtectControlGroupsEx=private -p DelegateNamespaces=cgroup --wait --pipe -- sh -c 'echo 0 >/sys/fs/cgroup/cgroup.pressure'
}

testcase_pid() {
    (! systemd-run -p PrivateUsersEx=self -p PrivatePIDs=yes --wait --pipe -- sh -c 'echo 5 >/proc/sys/kernel/ns_last_pid')
    systemd-run -p PrivateUsersEx=self -p PrivatePIDs=yes -p DelegateNamespaces=pid --wait --pipe -- sh -c 'echo 5 >/proc/sys/kernel/ns_last_pid'
}

testcase_uts() {
    (! systemd-run -p PrivateUsersEx=self -p ProtectHostnameEx=private --wait --pipe -- hostname abc)
    systemd-run -p PrivateUsersEx=self -p ProtectHostnameEx=private -p DelegateNamespaces=uts --wait --pipe -- hostname abc
}

testcase_implied_private_users_self() {
    # If not explicitly set PrivateUsers=self is implied.
    systemd-run -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- mount --bind /usr /home
    # If explicitly set it PrivateUsers= is not overridden.
    systemd-run -p PrivateUsersEx=identity -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait --pipe -- mount --bind /usr /home
    systemd-run -p PrivateUsersEx=identity -p PrivateMounts=yes -p DelegateNamespaces=mnt --wait bash -c 'test "$(cat /proc/self/uid_map)" == "         0          0      65536"'
}

testcase_multiple_features() {
    unsquashfs -no-xattrs -d /tmp/TEST-07-PID1-delegate-namespaces-root /usr/share/minimal_0.raw

    systemd-run \
        -p PrivatePIDs=yes \
        -p RootDirectory=/tmp/TEST-07-PID1-delegate-namespaces-root \
        -p ProcSubset=pid \
        -p BindReadOnlyPaths=/usr/share \
        -p NoNewPrivileges=yes \
        -p ProtectSystem=strict \
        -p User=testuser\
        -p Group=testuser \
        -p RuntimeDirectory=abc \
        -p StateDirectory=qed \
        -p InaccessiblePaths=/usr/include \
        -p TemporaryFileSystem=/home \
        -p PrivateTmp=yes \
        -p PrivateDevices=yes \
        -p PrivateNetwork=yes \
        -p PrivateUsersEx=self \
        -p PrivateIPC=yes \
        -p ProtectHostname=yes \
        -p ProtectClock=yes \
        -p ProtectKernelTunables=yes \
        -p ProtectKernelModules=yes \
        -p ProtectKernelLogs=yes \
        -p ProtectControlGroupsEx=private \
        -p LockPersonality=yes \
        -p Environment=ABC=QED \
        -p DelegateNamespaces=yes \
        --wait \
        --pipe \
        grep MARKER=1 /etc/os-release

    rm -rf /tmp/TEST-07-PID1-delegate-namespaces-root
}
