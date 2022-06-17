#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Let's run this test only if the "memory.oom.group" cgroupfs attribute
# exists. This test is a bit too strict, since the "memory.events"/"oom_kill"
# logic has been around since a longer time than "memory.oom.group", but it's
# an easier thing to test for, and also: let's not get confused by older
# kernels where the concept was still new.

if test -f /sys/fs/cgroup/system.slice/testsuite-32.service/memory.oom.group; then
    systemd-analyze log-level debug

    # Run a service that is guaranteed to be the first candidate for OOM killing
    systemd-run --unit=oomtest.service \
                -p Type=exec -p OOMScoreAdjust=1000 -p OOMPolicy=stop -p MemoryAccounting=yes \
                sleep infinity

    # Trigger an OOM killer run
    echo 1 >/proc/sys/kernel/sysrq
    echo f >/proc/sysrq-trigger

    while : ; do
        STATE="$(systemctl show -P ActiveState oomtest.service)"
        [ "$STATE" = "failed" ] && break
        sleep .5
    done

    RESULT="$(systemctl show -P Result oomtest.service)"
    test "$RESULT" = "oom-kill"

    systemd-analyze log-level info
fi

echo OK >/testok

exit 0
