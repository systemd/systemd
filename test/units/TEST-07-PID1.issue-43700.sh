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

MOUNT_POINT=/tmp/TEST-07-PID1-issue-43700
UNIT=$(systemd-escape --path "$MOUNT_POINT")
STAT_ERR=/tmp/TEST-07-PID1-issue-43700.stderr

at_exit() {
    set +e
    [[ -n "${WAITER_PID:-}" ]] && kill "$WAITER_PID"
    systemctl stop "$UNIT".automount "$UNIT".mount
    umount -l "$MOUNT_POINT"
    rm -f /run/systemd/system/"$UNIT".{auto,}mount
    systemctl daemon-reload
    systemctl reset-failed "$UNIT".automount "$UNIT".mount
    rm -rf "$MOUNT_POINT" "$STAT_ERR"
}

trap at_exit EXIT

# The file system type of the topmost mount at a path, read from mountinfo so that the check itself does not
# trigger the automount: statfs() would, as its path lookup asks for automounting.
fstype() {
    awk -v where="$1" '$5 == where { for (i = 7; $i != "-"; i++) {}; type = $(i + 1) } END { print type }' /proc/self/mountinfo
}

mkdir -p /run/systemd/system "$MOUNT_POINT"

cat >/run/systemd/system/"$UNIT".automount <<EOF
[Automount]
Where=$MOUNT_POINT
EOF

# An automount unit that still exists after daemon-reload stays armed and serves its mount point
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
ls "$MOUNT_POINT"
systemctl is-active "$UNIT".mount
[[ "$(fstype "$MOUNT_POINT")" == tmpfs ]]
systemctl stop "$UNIT".automount "$UNIT".mount

# A mount unit that never completes: the mount job waits for the nonexisting device
cat >/run/systemd/system/"$UNIT".mount <<EOF
[Mount]
What=/dev/disk/by-label/does-not-exist
Where=$MOUNT_POINT
Type=ext4
EOF
systemctl daemon-reload
systemctl start "$UNIT".automount

# Trigger the automount, which blocks in the kernel until PID 1 answers
timeout 30 stat "$MOUNT_POINT"/x 2>"$STAT_ERR" &
WAITER_PID=$!
timeout 10 bash -c "until systemctl list-jobs | grep -F '$UNIT.mount' >/dev/null; do sleep .5; done"
# The trigger is still blocked, so the reload below happens with a request pending
kill -0 "$WAITER_PID"

# Both units vanish while the mount job is still waiting for its device
TS="$(date '+%H:%M:%S')"
rm /run/systemd/system/"$UNIT".{auto,}mount
systemctl daemon-reload

# The waiter must fail promptly with the error the teardown sends, rather than hang until its timeout
# fires (rc=124) or fail for some other reason
rc=0
wait "$WAITER_PID" || rc=$?
unset WAITER_PID
[[ $rc -ne 0 && $rc -ne 124 ]]
grep -F 'Host is down' "$STAT_ERR"
journalctl --sync
journalctl -b --since "$TS" _PID=1 --grep "Unit file vanished, tearing down automount point '$MOUNT_POINT'"

# The autofs mount point is gone as well
! mountpoint -q "$MOUNT_POINT"
