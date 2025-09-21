#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

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
#!/usr/bin/env bash
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
systemctl reload systemd-journald.service

run_testcases

touch /testok
