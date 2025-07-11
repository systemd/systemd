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

    trap teardown_test_dependencies RETURN

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

testcase_issue_20329() {
    # test that handling of mount start jobs is delayed when /proc/self/mouninfo monitor is rate limited

    local tmpdir unit
    tmpdir="$(mktemp -d)"
    unit=$(systemd-escape --suffix mount --path "$tmpdir")

    # Set up test mount unit
    cat >/run/systemd/system/"$unit" <<EOF
[Mount]
What=tmpfs
Where=$tmpdir
Type=tmpfs
Options=defaults,nofail
EOF

    # Start the unit
    systemctl daemon-reload
    systemctl start "$unit"

    [[ "$(systemctl show --property SubState --value "$unit")" = "mounted" ]] || {
        echo >&2 "Test mount \"$unit\" unit isn't mounted"
        return 1
    }
    mountpoint -q "$tmpdir"

    trap 'systemctl stop $unit' RETURN

    # Trigger the mount ratelimiting
    cd "$(mktemp -d)"
    mkdir foo
    for _ in {1..50}; do
        mount --bind foo foo
        umount foo
    done

    # Unmount the test mount and start it immediately again via systemd
    umount "$tmpdir"
    systemctl start "$unit"

    # Make sure it is seen as mounted by systemd and it actually is mounted
    [[ "$(systemctl show --property SubState --value "$unit")" = "mounted" ]] || {
        echo >&2 "Test mount \"$unit\" unit isn't in \"mounted\" state"
        return 1
    }

    mountpoint -q "$tmpdir" || {
        echo >&2 "Test mount \"$unit\" is in \"mounted\" state, actually is not mounted"
        return 1
    }
}

testcase_issue_23796() {
    # test for reexecuting with background mount job

    local mount_path mount_mytmpfs since

    mount_path="$(command -v mount 2>/dev/null)"
    mount_mytmpfs="${mount_path/\/bin/\/sbin}.mytmpfs"
    cat >"$mount_mytmpfs" <<EOF
#!/bin/bash
sleep ".\$RANDOM"
exec -- $mount_path -t tmpfs tmpfs "\$2"
EOF
    chmod +x "$mount_mytmpfs"

    mkdir -p /run/systemd/system
    cat >/run/systemd/system/tmp-hoge.mount <<EOF
[Mount]
What=mytmpfs
Where=/tmp/hoge
Type=mytmpfs
EOF

    # shellcheck disable=SC2064
    trap "rm -f /run/systemd/system/tmp-hoge.mount '$mount_mytmpfs'" RETURN

    journalctl --sync
    since="$(date '+%H:%M:%S')"

    for _ in {1..10}; do
        systemctl --no-block start tmp-hoge.mount
        sleep ".$RANDOM"
        systemctl daemon-reexec

        sleep 1

        if [[ "$(systemctl is-failed tmp-hoge.mount)" == "failed" ]] ||
           journalctl --since="$since" -u tmp-hoge.mount -q --grep "but there is no mount"; then
            exit 1
        fi

        systemctl stop tmp-hoge.mount
    done
}

testcase_long_path() {
    local long_path long_mnt ts

    # make sure we can handle mounts at very long paths such that mount unit name must be hashed to fall within our unit name limit
    long_path="$(printf "/$(printf "x%0.s" {1..255})%0.s" {1..7})"
    long_mnt="$(systemd-escape --suffix=mount --path "$long_path")"

    journalctl --sync
    ts="$(date '+%H:%M:%S')"

    mkdir -p "$long_path"
    mount -t tmpfs tmpfs "$long_path"
    systemctl daemon-reload

    # check that unit is active(mounted)
    systemctl --no-pager show -p SubState --value "$long_path" | grep -q mounted

    # check that relevant part of journal doesn't contain any errors related to unit
    [ "$(journalctl -b --since="$ts" --priority=err | grep -c "$long_mnt")" = "0" ]

    # check that we can successfully stop the mount unit
    systemctl stop "$long_path"
    rm -rf "$long_path"
}

testcase_mount_ratelimit() {
    local num_dirs=20
    local ts i

    # mount/unmount enough times to trigger the /proc/self/mountinfo parsing rate limiting

    for ((i = 0; i < num_dirs; i++)); do
        mkdir "/tmp/meow${i}"
    done

    # The following loop may produce many journal entries.
    # Let's process all pending entries before testing.
    journalctl --sync
    ts="$(date '+%H:%M:%S')"

    for ((i = 0; i < num_dirs; i++)); do
        mount -t tmpfs tmpfs "/tmp/meow${i}"
    done

    systemctl daemon-reload
    systemctl list-units -t mount tmp-meow* | grep -q tmp-meow

    for ((i = 0; i < num_dirs; i++)); do
        umount "/tmp/meow${i}"
    done

    # Figure out if we have entered the rate limit state.
    # If the infra is slow we might not enter the rate limit state; in that case skip the exit check.
    journalctl --sync
    if timeout 2m journalctl -u init.scope --since="$ts" -n all --follow | grep -m 1 -q -F '(mount-monitor-dispatch) entered rate limit'; then
        journalctl --sync
        timeout 2m journalctl -u init.scope --since="$ts" -n all --follow | grep -m 1 -q -F '(mount-monitor-dispatch) left rate limit'
    fi

    # Verify that the mount units are always cleaned up at the end.
    # Give some time for units to settle so we don't race between exiting the rate limit state and cleaning up the units.
    timeout 2m bash -c 'while systemctl list-units -t mount tmp-meow* | grep -q tmp-meow; do systemctl daemon-reload; sleep 10; done'
}

systemd-analyze log-level debug
systemd-analyze log-target journal

mkdir -p /run/systemd/journald.conf.d
cat >/run/systemd/journald.conf.d/99-ratelimit.conf <<EOF
[Journal]
RateLimitBurst=0
EOF
systemctl restart systemd-journald.service

run_testcases

touch /testok
