#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

teardown_issue_19983() (
    set +eux

    if mountpoint /tmp/issue19983; then
        umount /tmp/issue19983
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

    rm -f /tmp/testsuite-60-issue-19983-0.img
    rm -f /tmp/testsuite-60-issue-19983-1.img

    rm -f /run/systemd/system/tmp-issue19983.mount
    systemctl daemon-reload

    return 0
)

setup_loop() {
    truncate -s 30m "/tmp/testsuite-60-issue-19983-${1?}.img"
    sfdisk --wipe=always "/tmp/testsuite-60-issue-19983-${1?}.img" <<EOF
label:gpt

name="loop${1?}-part1"
EOF
    LOOP=$(losetup -P --show -f "/tmp/testsuite-60-issue-19983-${1?}.img")
    udevadm wait --settle --timeout=10 "${LOOP}p1"
    udevadm lock --device="${LOOP}p1" mkfs.ext4 -L "partname${1?}-1" "${LOOP}p1"
}

check_19983() {
    local escaped_0 escaped_1 after

    escaped_0=$(systemd-escape -p "${LOOP_0}p1")
    escaped_1=$(systemd-escape -p "${LOOP_1}p1")

    if [[ -f /run/systemd/system/tmp-issue19983.mount ]]; then
        after=$(systemctl show --property=After --value tmp-issue19983.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi

    # mount LOOP_0
    mount -t ext4 "${LOOP_0}p1" /tmp/issue19983
    sleep 1
    after=$(systemctl show --property=After --value tmp-issue19983.mount)
    assert_in "local-fs-pre.target" "$after"
    assert_not_in "remote-fs-pre.target" "$after"
    assert_not_in "network.target" "$after"
    assert_in "${escaped_0}.device" "$after"
    assert_in "blockdev@${escaped_0}.target" "$after"
    assert_not_in "${escaped_1}.device" "$after"
    assert_not_in "blockdev@${escaped_1}.target" "$after"
    umount /tmp/issue19983

    if [[ -f /run/systemd/system/tmp-issue19983.mount ]]; then
        after=$(systemctl show --property=After --value tmp-issue19983.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi

    # mount LOOP_1
    mount -t ext4 "${LOOP_1}p1" /tmp/issue19983
    sleep 1
    after=$(systemctl show --property=After --value tmp-issue19983.mount)
    assert_in "local-fs-pre.target" "$after"
    assert_not_in "remote-fs-pre.target" "$after"
    assert_not_in "network.target" "$after"
    assert_not_in "${escaped_0}.device" "$after"
    assert_not_in "blockdev@${escaped_0}.target" "$after"
    assert_in "${escaped_1}.device" "$after"
    assert_in "blockdev@${escaped_1}.target" "$after"
    umount /tmp/issue19983

    if [[ -f /run/systemd/system/tmp-issue19983.mount ]]; then
        after=$(systemctl show --property=After --value tmp-issue19983.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi

    # mount tmpfs
    mount -t tmpfs tmpfs /tmp/issue19983
    sleep 1
    after=$(systemctl show --property=After --value tmp-issue19983.mount)
    assert_in "local-fs-pre.target" "$after"
    assert_not_in "remote-fs-pre.target" "$after"
    assert_not_in "network.target" "$after"
    assert_not_in "${escaped_0}.device" "$after"
    assert_not_in "blockdev@${escaped_0}.target" "$after"
    assert_not_in "${escaped_1}.device" "$after"
    assert_not_in "blockdev@${escaped_1}.target" "$after"
    umount /tmp/issue19983

    if [[ -f /run/systemd/system/tmp-issue19983.mount ]]; then
        after=$(systemctl show --property=After --value tmp-issue19983.mount)
        assert_not_in "local-fs-pre.target" "$after"
        assert_in "remote-fs-pre.target" "$after"
        assert_in "network.target" "$after"
    fi
}

test_issue_19983() {
    if systemd-detect-virt --quiet --container; then
        echo "Skipping test_issue_19983 in container"
        return
    fi

    trap teardown_issue_19983 RETURN

    setup_loop 0
    LOOP_0="${LOOP}"
    LOOP=
    setup_loop 1
    LOOP_1="${LOOP}"
    LOOP=

    mkdir -p /tmp/issue19983

    # without .mount file
    check_19983

    # create .mount file
    mkdir -p /run/systemd/system
    cat >/run/systemd/system/tmp-issue19983.mount <<EOF
[Mount]
Where=/tmp/issue19983
What=192.168.0.1:/tmp/mnt
Type=nfs
EOF
    systemctl daemon-reload

    # with .mount file
    check_19983

}

test_issue_20329() {
    local tmpdir unit
    tmpdir="$(mktemp -d)"
    unit=$(systemd-escape --suffix mount --path "$tmpdir")

    # Set up test mount unit
    cat > /run/systemd/system/"$unit" <<EOF
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
    for ((i = 0; i < 50; i++)); do
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

: >/failed

systemd-analyze log-level debug
systemd-analyze log-target journal

NUM_DIRS=20

# make sure we can handle mounts at very long paths such that mount unit name must be hashed to fall within our unit name limit
LONGPATH="$(printf "/$(printf "x%0.s" {1..255})%0.s" {1..7})"
LONGMNT="$(systemd-escape --suffix=mount --path "$LONGPATH")"
TS="$(date '+%H:%M:%S')"

mkdir -p "$LONGPATH"
mount -t tmpfs tmpfs "$LONGPATH"
systemctl daemon-reload

# check that unit is active(mounted)
systemctl --no-pager show -p SubState --value "$LONGPATH" | grep -q mounted

# check that relevant part of journal doesn't contain any errors related to unit
[ "$(journalctl -b --since="$TS" --priority=err | grep -c "$LONGMNT")" = "0" ]

# check that we can successfully stop the mount unit
systemctl stop "$LONGPATH"
rm -rf "$LONGPATH"

# mount/unmount enough times to trigger the /proc/self/mountinfo parsing rate limiting

for ((i = 0; i < NUM_DIRS; i++)); do
    mkdir "/tmp/meow${i}"
done

TS="$(date '+%H:%M:%S')"

for ((i = 0; i < NUM_DIRS; i++)); do
    mount -t tmpfs tmpfs "/tmp/meow${i}"
done

systemctl daemon-reload
systemctl list-units -t mount tmp-meow* | grep -q tmp-meow

for ((i = 0; i < NUM_DIRS; i++)); do
    umount "/tmp/meow${i}"
done

# Figure out if we have entered the rate limit state.
# If the infra is slow we might not enter the rate limit state; in that case skip the exit check.
if timeout 2m bash -c "while ! journalctl -u init.scope --since=$TS | grep -q '(mount-monitor-dispatch) entered rate limit'; do sleep 1; done"; then
    timeout 2m bash -c "while ! journalctl -u init.scope --since=$TS | grep -q '(mount-monitor-dispatch) left rate limit'; do sleep 1; done"
fi

# Verify that the mount units are always cleaned up at the end.
# Give some time for units to settle so we don't race between exiting the rate limit state and cleaning up the units.
timeout 2m bash -c 'while systemctl list-units -t mount tmp-meow* | grep -q tmp-meow; do systemctl daemon-reload; sleep 10; done'

test_issue_19983

# test that handling of mount start jobs is delayed when /proc/self/mouninfo monitor is rate limited
test_issue_20329

systemd-analyze log-level info

touch /testok
rm /failed
