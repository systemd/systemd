#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

: >/failed

mkfifo /tmp/syncfifo1 /tmp/syncfifo2

sync_in() {
    read -r x < /tmp/syncfifo1
    test "$x" = "$1"
}

sync_out() {
    echo "$1" > /tmp/syncfifo2
}

export SYSTEMD_LOG_LEVEL=debug

systemctl --no-block start notify.service

sync_in a

assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"
assert_eq "$(systemctl show notify.service -p StatusText --value)" "Test starts"

sync_out b
sync_in c

assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "main"
assert_eq "$(systemctl show notify.service -p StatusText --value)" "Sending READY=1 in an unprivileged process"
assert_rc 3 systemctl --quiet is-active notify.service

sync_out d
sync_in e

systemctl --quiet is-active notify.service
assert_eq "$(systemctl show notify.service -p StatusText --value)" "OK"
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "none"

systemctl stop notify.service
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"

rm /tmp/syncfifo1 /tmp/syncfifo2

# Now test basic fdstore behaviour

MYSCRIPT="/tmp/myscript$RANDOM.sh"
cat >> "$MYSCRIPT" <<'EOF'
#!/usr/bin/env bash
set -eux
set -o pipefail
N="/tmp/$RANDOM"
echo $RANDOM > "$N"
systemd-notify --fd=4 --fdname=quux --pid=parent 4< "$N"
rm "$N"
systemd-notify --ready
exec sleep infinity
EOF

chmod +x "$MYSCRIPT"

MYUNIT="myunit$RANDOM.service"
systemd-run -u "$MYUNIT" -p Type=notify -p StandardOutput=journal+console -p StandardError=journal+console -p FileDescriptorStoreMax=7 "$MYSCRIPT"

test "$(systemd-analyze fdstore "$MYUNIT" | wc -l)" -eq 2
systemd-analyze fdstore "$MYUNIT" --json=short
systemd-analyze fdstore "$MYUNIT" --json=short | grep -P -q '\[{"fdname":"quux","type":.*,"devno":\[.*\],"inode":.*,"rdevno":null,"path":"/tmp/.*","flags":"ro"}\]'

systemctl stop "$MYUNIT"
rm "$MYSCRIPT"

# Test fdstore pinning (this will pull in fdstore-pin.service fdstore-nopin.service)
systemctl start fdstore-pin.target

assert_eq "$(systemctl show fdstore-pin.service -P FileDescriptorStorePreserve)" yes
assert_eq "$(systemctl show fdstore-nopin.service -P FileDescriptorStorePreserve)" restart
assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" running
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" running

# The file descriptor store should survive service restarts
systemctl restart fdstore-pin.service fdstore-nopin.service

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" running
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" running

# It should not survive the service stop plus a later start (unless pinned)
systemctl stop fdstore-pin.service fdstore-nopin.service

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" resources-pinned
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" dead

systemctl start fdstore-pin.service fdstore-nopin.service

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" running
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" running

systemctl stop fdstore-pin.service fdstore-nopin.service

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" resources-pinned
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" dead

systemctl clean fdstore-pin.service --what=fdstore

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" dead
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" dead

touch /testok
rm /failed

exit 0
