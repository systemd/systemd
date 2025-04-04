#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if [[ "$(get_cgroup_hierarchy)" != unified ]]; then
    echo "Skipping $0 as we're not running with the unified cgroup hierarchy"
    exit 0
fi

if systemd-detect-virt --container --quiet; then
    echo "Skipping $0 as we're running on container."
    exit 0
fi

get_future_seconds() {
        SEC=$(date +%S)

        if [[ ${SEC:0:1} == "0" ]]; then
                # Strip off the leading "0"
                SEC=${SEC:1:2}
        fi

        # Select a time shortly in the future.  We don't want to wait too long for the timer
        SEC=$((SEC+2))

        if (( SEC > 59 )); then
                # Handle overflow
                SEC=$((SEC-60))
        fi
}

testcase_persist_off() {
        SLICE="system.slice"
        UNIT="timer-$RANDOM"
        get_future_seconds

        busctl set-property org.freedesktop.systemd1 \
                            /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                            DefaultPersistTimerCgroups b false

        assert_eq "$(busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager DefaultPersistTimerCgroups)" "b false"

        # Create a timer that will run very soon, then every minute after that
        assert_ok systemd-run --unit "$UNIT" \
                              --slice "$SLICE" \
                              --on-calendar "*-*-* *:*:$SEC" \
                              true

        # Wait for the timer to have run once and thus created the cgroup.  Since persist is
        # disabled, the cgroup should not exist when the service isn't running
        sleep 8

        assert_fail test -d /sys/fs/cgroup/$SLICE/$UNIT.service

        systemctl stop "$UNIT.timer"

        sleep 1

        assert_fail test -d /sys/fs/cgroup/$SLICE/$UNIT.service
}

testcase_persist_on() {
        SLICE="system.slice"
        UNIT="timer-$RANDOM"
        get_future_seconds

        busctl set-property org.freedesktop.systemd1 \
                            /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager \
                            DefaultPersistTimerCgroups b true

        assert_eq "$(busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager DefaultPersistTimerCgroups)" "b true"

        # Create a timer that will run very soon, then every minute after that
        assert_ok systemd-run --unit "$UNIT" \
                              --slice "$SLICE" \
                              --on-calendar "*-*-* *:*:$SEC" \
                              true

        # wait for the timer to have run once and thus created the cgroup
        sleep 8

        assert_ok test -d /sys/fs/cgroup/$SLICE/$UNIT.service

        systemctl stop "$UNIT.timer"

        sleep 1

        assert_fail test -d /sys/fs/cgroup/$SLICE/$UNIT.service
}

run_testcases

touch /testok
