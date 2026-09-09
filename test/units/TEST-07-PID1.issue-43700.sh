#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# An automount unit that vanishes across daemon-reload must not leave its autofs mount point armed.
# See https://github.com/systemd/systemd/issues/43700

MOUNT_POINT=/tmp/hang
# Mount and automount unit names must match Where=
UNIT=tmp-hang

at_exit() {
    set +e
    [[ -n "${WAITER_PID:-}" ]] && kill "$WAITER_PID"
    umount -l "$MOUNT_POINT"
    rm -f /run/systemd/system/"$UNIT".{auto,}mount
    systemctl daemon-reload
    rmdir "$MOUNT_POINT"
}

trap at_exit EXIT

mkdir -p /run/systemd/system "$MOUNT_POINT"

# A mount unit that never completes: the mount job waits for the nonexisting device
cat >/run/systemd/system/"$UNIT".mount <<EOF
[Mount]
What=/dev/disk/by-label/does-not-exist
Where=$MOUNT_POINT
Type=ext4
EOF

cat >/run/systemd/system/"$UNIT".automount <<EOF
[Automount]
Where=$MOUNT_POINT
EOF

systemctl daemon-reload
systemctl start "$UNIT".automount

# Trigger the automount, which blocks in the kernel until PID 1 answers
timeout 30 stat "$MOUNT_POINT"/x &
WAITER_PID=$!
timeout 5 bash -c "until systemctl list-jobs | grep -q '$UNIT.mount'; do sleep .5; done"
# The trigger is still blocked, so the reload below happens with a request pending
kill -0 "$WAITER_PID"

# Both units vanish while the mount job is still waiting for its device
rm /run/systemd/system/"$UNIT".{auto,}mount
systemctl daemon-reload

# The waiter must fail promptly rather than hang until its timeout fires (rc=124)
set +e
wait "$WAITER_PID"
rc=$?
set -e
unset WAITER_PID
[[ $rc -ne 0 && $rc -ne 124 ]]

# The autofs mount point is gone as well
! mountpoint -q "$MOUNT_POINT"
