#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

at_exit() {
    # "Safety net" - check for any coredumps which might have not caused dfuzzer
    # to stop & return an error (we need to do this now before truncating the
    # journal)
    local found_cd=0
    while read -r exe; do
        coredumctl info "$exe"
        found_cd=1
    done < <(coredumpctl -F COREDUMP_EXE | sort -u)
    [[ $found_cd -eq 0 ]] || exit 1

    # Limit the maximum journal size (because fuzzing)
    journalctl --rotate --vacuum-size=16M
}

trap at_exit EXIT

systemctl log-level info

# TODO
#   * check for possibly newly introduced buses?
BUS_LIST=(
    org.freedesktop.home1
    org.freedesktop.hostname1
    org.freedesktop.import1
    org.freedesktop.locale1
    org.freedesktop.login1
    org.freedesktop.machine1
    org.freedesktop.network1
    org.freedesktop.oom1
    org.freedesktop.portable1
    org.freedesktop.resolve1
    org.freedesktop.systemd1
    org.freedesktop.timedate1
    org.freedesktop.timesync1
)

SESSION_BUS_LIST=(
    org.freedesktop.systemd1
)

# Configure dfuzzer suppressions to filter out interfaces which might degrade
# or straight up kill the test machine
cat >/etc/dfuzzer.conf <<EOF
[org.freedesktop.login1]
Halt destructive
HaltWithFlags destructive
Hibernate destructive
HibernateWithFlags destructive
HybridSleep destructive
HybridSleepWithFlags destructive
KillSession destructive
KillUser destructive
LockSession destructive
LockSessions destructive
PowerOff destructive
PowerOffWithFlags destructive
Reboot destructive
RebootWithFlags destructive
ReleaseSession destructive
ScheduleShutdown destructive
Suspend destructive
SuspendThenHibernate destructive
SuspendThenHibernateWithFlags destructive
SuspendWithFlags destructive
TerminateSeat destructive
TerminateSession destructive
TerminateUser destructive

[org.freedesktop.timedate1]
SetLocalRTC destructive (screws up the RTC & system time)
SetNTP destructive (disables systemd-timesyncd)
EOF

# Overmount /var/lib/machines with a size-limited tmpfs, as fuzzing
# the org.freedesktop.machine1 stuff makes quite a mess
mount -t tmpfs -o size=50M tmpfs /var/lib/machines

# Fuzz both the system and the session buses (where applicable)
for bus in "${BUS_LIST[@]}"; do
    echo "Bus: $bus (system)"
    # Activate the name (if it's activatable) before fuzzing it
    busctl --no-pager introspect "$bus" /
    # Note: explicitly set $HOME here to avoid dfuzzer crashing until
    #       https://github.com/matusmarhefka/dfuzzer/pull/9 is merged
    systemd-run -E HOME=/root --pipe --wait -- dfuzzer -v -m 524288 -n "$bus"
done

umount /var/lib/machines

for bus in "${SESSION_BUS_LIST[@]}"; do
    echo "Bus: $bus (session)"
    # Activate the name (if it's activatable) before fuzzing it
    busctl --no-pager introspect "$bus" /
    systemd-run --machine 'testuser@.host' --user --pipe --wait -- dfuzzer -v -m 524288 -n "$bus"
done

echo OK >/testok

exit 0
