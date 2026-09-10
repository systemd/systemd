#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# An automount unit that vanishes across daemon-reload must not leave its autofs mount point armed,
# there's nothing left to answer it.
# See https://github.com/systemd/systemd/issues/43700

# PID 1 declares automount units unsupported without this device, e.g. in the nspawn containers CI runs in
if [[ ! -e /dev/autofs ]]; then
    echo "autofs is not available, skipping automount tests"
    exit 77
fi

# The errno text asserted below is strerror()'s
export LC_ALL=C

MOUNT_POINT=/tmp/TEST-07-PID1-issue-43700
UNIT=$(systemd-escape --path "$MOUNT_POINT")
STAT_ERR=/tmp/TEST-07-PID1-issue-43700.stderr
CURSOR=/tmp/TEST-07-PID1-issue-43700.cursor
GENERATOR=/run/systemd/system-generators/TEST-07-PID1-issue-43700
# Not below /tmp: PID 1 runs generators with a private one, so we would never see these
MARKER=/run/TEST-07-PID1-issue-43700.reloading
RELEASE=/run/TEST-07-PID1-issue-43700.release

at_exit() {
    set +e
    [[ -n "${WAITER_PID:-}" ]] && kill "$WAITER_PID"
    systemctl stop "$UNIT".automount "$UNIT".mount
    # A file system may sit on top of an armed autofs; detach both without stepping into either
    while [[ -n "$(fstype "$MOUNT_POINT")" ]]; do
        umount -l "$MOUNT_POINT" || break
    done
    rm -f /run/systemd/system/"$UNIT".{auto,}mount "$STAT_ERR" "$CURSOR" "$GENERATOR" "$MARKER" "$RELEASE"
    systemctl unmask "$UNIT".automount
    systemctl daemon-reload
    systemctl reset-failed "$UNIT".automount "$UNIT".mount
    rmdir "$MOUNT_POINT"
}

trap at_exit EXIT

# The file system type of the topmost mount at a path, read from mountinfo so that the check itself does not
# trigger the automount: statfs() would, as its path lookup asks for automounting.
fstype() {
    awk -v where="$1" '$5 == where { for (i = 7; $i != "-"; i++) {}; type = $(i + 1) } END { print type }' /proc/self/mountinfo
}

write_automount() {
    cat >/run/systemd/system/"$UNIT".automount <<EOF
[Automount]
Where=$MOUNT_POINT
EOF
}

# A mount unit that never completes: the mount job waits for the nonexisting device
write_hanging_mount() {
    cat >/run/systemd/system/"$UNIT".mount <<EOF
[Mount]
What=/dev/disk/by-label/does-not-exist
Where=$MOUNT_POINT
Type=ext4
EOF
}

mkdir -p /run/systemd/system "$MOUNT_POINT"

# An automount unit that still exists after daemon-reload stays armed and serves its mount point
write_automount
cat >/run/systemd/system/"$UNIT".mount <<EOF
[Mount]
What=tmpfs
Where=$MOUNT_POINT
Type=tmpfs
EOF

systemctl daemon-reload
systemctl start "$UNIT".automount
systemctl daemon-reload
systemctl is-active "$UNIT".automount
[[ "$(fstype "$MOUNT_POINT")" == autofs ]]
# Only PID 1 can answer this, and a regression that leaves the autofs unserved would block it forever,
# taking the exit trap and the rest of TEST-07-PID1 with it
timeout -k 5 -s KILL 60 ls "$MOUNT_POINT"
systemctl is-active "$UNIT".mount
[[ "$(fstype "$MOUNT_POINT")" == tmpfs ]]

# PID 1's log lines are matched without _PID=1: right after a daemon-reexec it still logs to kmsg, and the
# journal's kernel transport carries no trusted PID. Every match below is bounded by a cursor, which each
# journalctl advances past the line it found, as the cases log the same message more than once.
journalctl -n 0 --cursor-file="$CURSOR"

# Vanishing underneath a file system already mounted on top leaves that file system alone
rm /run/systemd/system/"$UNIT".{auto,}mount
systemctl daemon-reload
journalctl --sync
journalctl --cursor-file="$CURSOR" --grep "abandoning automount point '$MOUNT_POINT'"
# The unit went away with its file rather than sticking around as a failed one
(! systemctl is-active "$UNIT".automount)
(! systemctl is-failed "$UNIT".automount)
systemctl is-active "$UNIT".mount
[[ "$(fstype "$MOUNT_POINT")" == tmpfs ]]
ls "$MOUNT_POINT"
# The autofs underneath was given up: once exposed again, accessing it must not hang
umount "$MOUNT_POINT"
[[ "$(fstype "$MOUNT_POINT")" == autofs ]]
rc=0
timeout -k 5 -s KILL 60 ls "$MOUNT_POINT" || rc=$?
[[ $rc -ne 137 ]]
umount -l "$MOUNT_POINT"
# Both mounts went away behind PID 1's back, and it processes mount table changes rate-limited. Wait for
# it to catch up, or the next case's mount unit starts out as already mounted and never gets a job.
timeout 30 bash -c "until [[ \$(systemctl show -p ActiveState --value '$UNIT.mount') == inactive ]]; do sleep .5; done"

# Vanishing while a request waits for the mount fails the request and disarms the mount point
for reload in daemon-reload daemon-reexec; do
    write_automount
    write_hanging_mount
    systemctl daemon-reload
    systemctl start "$UNIT".automount

    # Trigger the automount, which blocks in the kernel until PID 1 answers. Only SIGKILL gets it out of
    # that wait before then, so a regression must fail the test here rather than hang it.
    timeout -k 5 -s KILL 60 stat "$MOUNT_POINT"/x 2>"$STAT_ERR" &
    WAITER_PID=$!
    timeout 10 bash -c "until systemctl list-jobs | grep -F '$UNIT.mount' >/dev/null; do sleep .5; done"

    # Both units vanish while the mount job is still waiting for its device
    rm /run/systemd/system/"$UNIT".{auto,}mount
    systemctl "$reload"

    # The waiter must fail promptly with the error the teardown sends, rather than hang until its timeout
    # kills it (rc=137) or fail for some other reason
    rc=0
    wait "$WAITER_PID" || rc=$?
    unset WAITER_PID
    [[ $rc -ne 0 && $rc -ne 137 ]]
    grep -F 'Host is down' "$STAT_ERR"
    journalctl --sync
    journalctl --cursor-file="$CURSOR" --grep "tearing down automount point '$MOUNT_POINT'"
    (! systemctl is-active "$UNIT".automount)
    (! systemctl is-failed "$UNIT".automount)

    # The autofs mount point is gone as well
    [[ -z "$(fstype "$MOUNT_POINT")" ]]
done

# Masking counts as vanishing too: the unit stops being loaded, so nothing serves the mount point anymore
write_automount
write_hanging_mount
systemctl daemon-reload
systemctl start "$UNIT".automount
[[ "$(fstype "$MOUNT_POINT")" == autofs ]]
systemctl mask "$UNIT".automount
systemctl daemon-reload
journalctl --sync
journalctl --cursor-file="$CURSOR" --grep "tearing down automount point '$MOUNT_POINT'"
(! systemctl is-active "$UNIT".automount)
[[ -z "$(fstype "$MOUNT_POINT")" ]]
systemctl unmask "$UNIT".automount
rm /run/systemd/system/"$UNIT".{auto,}mount
systemctl daemon-reload

# A request arriving while PID 1 reloads sits unread in the pipe when the vanished unit is torn down, so
# its token is unknown to PID 1. It must still be failed rather than left blocked. Generators run
# synchronously, so one that waits for us holds the reload open for as long as it takes to get a request
# into that window.
write_automount
write_hanging_mount
systemctl daemon-reload
systemctl start "$UNIT".automount

mkdir -p "$(dirname "$GENERATOR")"
cat >"$GENERATOR" <<EOF
#!/bin/sh
touch $MARKER
# Wait for the test to park its request, but give up eventually rather than hold PID 1 forever if the
# test died before it got there
i=0
while [ ! -e $RELEASE ] && [ \$i -lt 200 ]; do
    i=\$((i + 1))
    sleep .1
done
EOF
chmod +x "$GENERATOR"
rm /run/systemd/system/"$UNIT".{auto,}mount
rm -f "$MARKER" "$RELEASE"
systemctl daemon-reload &
RELOAD_PID=$!
# Wait for the generator to run: PID 1 dispatches no events until the reload is through, so a request
# made from here on is one it cannot have read. Assuming that instead of waiting for it would make the
# case pass on an answered token, which fails with the same ENOENT.
timeout 30 bash -c "until [[ -e $MARKER ]]; do sleep .1; done"
timeout -k 5 -s KILL 60 stat "$MOUNT_POINT"/x 2>"$STAT_ERR" &
WAITER_PID=$!
# The request is parked in the kernel while the autofs is still armed, i.e. before PID 1 got to the
# teardown, so it was made inside the reload and PID 1 never read it. These waits are unhurried because
# the generator holds the reload until they are through. timeout(1) has to fork stat(1) first, and
# /proc/PID/wchan needs a kernel with CONFIG_KALLSYMS to name the frame.
timeout 10 bash -c "until pgrep -P $WAITER_PID >/dev/null; do sleep .1; done"
STAT_PID=$(pgrep -P "$WAITER_PID")
timeout 10 bash -c "until grep autofs /proc/$STAT_PID/wchan >/dev/null; do sleep .2; done"
[[ "$(fstype "$MOUNT_POINT")" == autofs ]]
touch "$RELEASE"
wait "$RELOAD_PID"
rm "$GENERATOR" "$MARKER" "$RELEASE"

# The kernel fails unread requests with ENOENT once the autofs is catatonic
rc=0
wait "$WAITER_PID" || rc=$?
unset WAITER_PID
[[ $rc -ne 0 && $rc -ne 137 ]]
grep -F 'No such file or directory' "$STAT_ERR"
journalctl --sync
journalctl --cursor-file="$CURSOR" --grep "tearing down automount point '$MOUNT_POINT'"
(! systemctl is-active "$UNIT".automount)
(! systemctl is-failed "$UNIT".automount)
[[ -z "$(fstype "$MOUNT_POINT")" ]]
