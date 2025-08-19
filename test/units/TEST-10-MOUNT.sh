#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

teardown_test_dependencies() (
    set +eux

    if mountpoint /tmp/deptest; then
        umount /tmp/deptest
    fi

    if [[ -n "${LOOP}" ]]; then
        losetup -d "${LOOP}" || :
    fi
    if [[ -n "${LOOP_0}" ]]; then
        losetup -d "${LOOP_0}" || :
    fi
    if [[ -n "${LOOP_1}" ]]; then
        losetup -d "${LOOP_1}" || :
    fi

    rm -f /tmp/TEST-60-MOUNT-RATELIMIT-dependencies-0.img
    rm -f /tmp/TEST-60-MOUNT-RATELIMIT-dependencies-1.img

    rm -f /run/systemd/system/tmp-deptest.mount
    systemctl daemon-reload

    return 0
)

setup_loop() {
    truncate -s 30m "/tmp/TEST-60-MOUNT-RATELIMIT-dependencies-${1?}.img"
    sfdisk --wipe=always "/tmp/TEST-60-MOUNT-RATELIMIT-dependencies-${1?}.img" <<EOF
label:gpt

name="loop${1?}-part1"
EOF
    LOOP=$(losetup -P --show -f "/tmp/TEST-60-MOUNT-RATELIMIT-dependencies-${1?}.img")
    udevadm wait --settle --timeout=30 "${LOOP}"
    udevadm lock --timeout=30 --device="${LOOP}" mkfs.ext4 -L "partname${1?}-1" "${LOOP}p1"
}

check_dependencies() {
    local escaped_0 escaped_1 after

    escaped_0=$(systemd-escape -p "${LOOP_0}p1")
    escaped_1=$(systemd-escape -p "${LOOP_1}p1")

    if [[ -f /run/systemd/system/tmp-deptest.mount ]]; then
        after=$(systemctl show --property=After --value tmp-deptest.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi

    # mount LOOP_0
    mount -t ext4 "${LOOP_0}p1" /tmp/deptest
    timeout 10 bash -c 'until systemctl -q is-active tmp-deptest.mount; do sleep .1; done'
    after=$(systemctl show --property=After --value tmp-deptest.mount)
    assert_in "local-fs-pre.target" "$after"
    assert_not_in "remote-fs-pre.target" "$after"
    assert_not_in "network.target" "$after"
    assert_in "${escaped_0}.device" "$after"
    assert_in "blockdev@${escaped_0}.target" "$after"
    assert_not_in "${escaped_1}.device" "$after"
    assert_not_in "blockdev@${escaped_1}.target" "$after"
    systemctl stop tmp-deptest.mount

    if [[ -f /run/systemd/system/tmp-deptest.mount ]]; then
        after=$(systemctl show --property=After --value tmp-deptest.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi

    # mount LOOP_1 (using fake _netdev option)
    mount -t ext4 -o _netdev "${LOOP_1}p1" /tmp/deptest
    timeout 10 bash -c 'until systemctl -q is-active tmp-deptest.mount; do sleep .1; done'
    # When a device is mounted with userspace options such as _netdev, even when the mount event source is
    # triggered, only /proc/self/mountinfo may be updated, and /run/mount/utab may not be updated yet.
    # Hence, the mount unit may be created/updated without the userspace options. In that case, the mount
    # event source will be retriggered when /run/mount/utab is updated, and the mount unit will be updated
    # again with the userspace options. Typically, the window between the two calls is very short, but when
    # the mount event source is ratelimited after the first event, processing the second event may be delayed
    # about 1 second. Hence, here we need to wait for a while.
    timeout 10 bash -c 'until systemctl show --property=After --value tmp-deptest.mount | grep -q -F remote-fs-pre.target; do sleep .1; done'
    after=$(systemctl show --property=After --value tmp-deptest.mount)
    assert_not_in "local-fs-pre.target" "$after"
    assert_in "remote-fs-pre.target" "$after"
    assert_in "network.target" "$after"
    assert_not_in "${escaped_0}.device" "$after"
    assert_not_in "blockdev@${escaped_0}.target" "$after"
    assert_in "${escaped_1}.device" "$after"
    assert_in "blockdev@${escaped_1}.target" "$after"
    systemctl stop tmp-deptest.mount

    if [[ -f /run/systemd/system/tmp-deptest.mount ]]; then
        after=$(systemctl show --property=After --value tmp-deptest.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi

    # mount tmpfs
    mount -t tmpfs tmpfs /tmp/deptest
    timeout 10 bash -c 'until systemctl -q is-active tmp-deptest.mount; do sleep .1; done'
    after=$(systemctl show --property=After --value tmp-deptest.mount)
    assert_in "local-fs-pre.target" "$after"
    assert_not_in "remote-fs-pre.target" "$after"
    assert_not_in "network.target" "$after"
    assert_not_in "${escaped_0}.device" "$after"
    assert_not_in "blockdev@${escaped_0}.target" "$after"
    assert_not_in "${escaped_1}.device" "$after"
    assert_not_in "blockdev@${escaped_1}.target" "$after"
    systemctl stop tmp-deptest.mount

    if [[ -f /run/systemd/system/tmp-deptest.mount ]]; then
        after=$(systemctl show --property=After --value tmp-deptest.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi
}

testcase_dependencies() {
    # test for issue #19983 and #23552.

    if systemd-detect-virt --quiet --container; then
        echo "Skipping test_dependencies in container"
        return
    fi

    trap teardown_test_dependencies RETURN EXIT ERR INT TERM

    setup_loop 0
    LOOP_0="${LOOP}"
    LOOP=
    setup_loop 1
    LOOP_1="${LOOP}"
    LOOP=

    mkdir -p /tmp/deptest

    # without .mount file
    check_dependencies

    # create .mount file
    mkdir -p /run/systemd/system
    cat >/run/systemd/system/tmp-deptest.mount <<EOF
[Mount]
Where=/tmp/deptest
What=192.168.0.1:/tmp/mnt
Type=nfs
EOF
    systemctl daemon-reload

    # with .mount file
    check_dependencies
}

run_testcases

touch /testok
