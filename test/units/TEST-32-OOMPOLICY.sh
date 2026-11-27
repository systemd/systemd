#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Let's run this test only if the "memory.oom.group" cgroupfs attribute
# exists. This test is a bit too strict, since the "memory.events"/"oom_kill"
# logic has been around since a longer time than "memory.oom.group", but it's
# an easier thing to test for, and also: let's not get confused by older
# kernels where the concept was still new.

if test -f /sys/fs/cgroup/system.slice/TEST-32-OOMPOLICY.service/memory.oom.group; then
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

    # A process killed by the kernel OOM killer within the unit's cgroup should also be reported with
    # the 'oom-kill' result when OOMPolicy=continue, so that Restart= can react to it.
    # shellcheck disable=SC2016
    (! systemd-run --wait --unit=oomtest-continue.service \
                -p Type=exec -p OOMPolicy=continue -p MemoryAccounting=yes -p MemoryMax=16M \
                -p MemorySwapMax=0 -p MemoryZSwapMax=0 \
                bash -c 's=$(printf "%134217728s" x); echo "${#s}"')

    RESULT="$(systemctl show oomtest-continue.service -P Result)"
    test "$RESULT" = "oom-kill"

    # Restart=on-oom-kill should restart the service when its processes are killed by an OOM killer...
    # shellcheck disable=SC2016
    systemd-run --unit=oomtest-restart.service \
                -p Type=exec -p OOMPolicy=continue -p MemoryAccounting=yes -p MemoryMax=16M \
                -p MemorySwapMax=0 -p MemoryZSwapMax=0 \
                -p Restart=on-oom-kill -p RestartSec=1s \
                bash -c 's=$(printf "%134217728s" x); echo "${#s}"'

    NRESTARTS=0
    for _ in $(seq 30) ; do
        NRESTARTS="$(systemctl show -P NRestarts oomtest-restart.service)"
        [ "$NRESTARTS" -ge 1 ] && break
        sleep 1
    done
    test "$NRESTARTS" -ge 1

    systemctl stop oomtest-restart.service

    # ...but not when it is killed by a signal for other reasons.
    systemd-run --unit=oomtest-norestart.service \
                -p Type=exec -p OOMPolicy=continue -p MemoryAccounting=yes \
                -p Restart=on-oom-kill -p RestartSec=1s \
                sleep infinity

    systemctl kill --signal=SIGKILL oomtest-norestart.service

    STATE=running
    for _ in $(seq 30) ; do
        STATE="$(systemctl show -P ActiveState oomtest-norestart.service)"
        [ "$STATE" = "failed" ] && break
        sleep .5
    done
    test "$STATE" = "failed"

    RESULT="$(systemctl show oomtest-norestart.service -P Result)"
    test "$RESULT" = "signal"

    NRESTARTS="$(systemctl show -P NRestarts oomtest-norestart.service)"
    test "$NRESTARTS" = "0"
fi

touch /testok
