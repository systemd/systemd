#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check if the colored --version output behaves correctly
SYSTEMD_COLORS=256 systemctl --version

# Check if we properly differentiate between a full systemd setup and a "light"
# version of it that's done during daemon-reexec
#
# See: https://github.com/systemd/systemd/issues/27106
if systemd-detect-virt -q --container; then
    # We initialize /run/systemd/container only during a full setup
    test -e /run/systemd/container
    cp -afv /run/systemd/container /tmp/container
    rm -fv /run/systemd/container
    systemctl daemon-reexec
    test ! -e /run/systemd/container
    cp -afv /tmp/container /run/systemd/container
else
    # We bring the loopback netdev up only during a full setup, so it should
    # not get brought back up during reexec if we disable it beforehand
    [[ "$(ip -o link show lo)" =~ LOOPBACK,UP ]]
    ip link set lo down
    [[ "$(ip -o link show lo)" =~ state\ DOWN ]]
    systemctl daemon-reexec
    [[ "$(ip -o link show lo)" =~ state\ DOWN ]]
    ip link set lo up

    # We also disable coredumps only during a full setup
    sysctl -w kernel.core_pattern=dont-overwrite-me
    systemctl daemon-reexec
    diff <(echo dont-overwrite-me) <(sysctl --values kernel.core_pattern)
fi

# Collect failed units & do one daemon-reload to a basic sanity check
systemctl --state=failed --no-legend --no-pager | tee /failed
test ! -s /failed
systemctl daemon-reload

# Check that the early setup is actually skipped on reexec.
# If the early setup is done more than once, then several timestamps,
# e.g. SecurityStartTimestamp, are re-initialized, and causes an ABRT
# of systemd-analyze blame. See issue #27187.
systemd-analyze blame

# Test for 'systemd-update-utmp runlevel' vs 'systemctl daemon-reexec'.
# See issue #27163.
# shellcheck disable=SC2034
if [[ -x /usr/lib/systemd/systemd-update-utmp ]]; then
    for _ in {0..10}; do
        systemctl daemon-reexec &
        pid_reexec=$!
        # shellcheck disable=SC2034
        for _ in {0..10}; do
            SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/systemd-update-utmp runlevel
        done
        wait "$pid_reexec"
    done
fi

touch /testok
