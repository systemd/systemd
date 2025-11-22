#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

mkfifo /tmp/syncfifo1 /tmp/syncfifo2

sync_in() {
    read -r x < /tmp/syncfifo1
    test "$x" = "$1"
}

sync_out() {
    echo "$1" >/tmp/syncfifo2
}

export SYSTEMD_LOG_LEVEL=debug

# Test NotifyAccess= override through sd_notify()

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
[[ "$(systemctl show notify.service -P StatusText)" != BOGUS* ]]

assert_eq "$(systemctl show notify.service -P StatusErrno)" "1"
assert_eq "$(systemctl show notify.service -P StatusBusError)" "org.freedesktop.DBus.Error.InvalidArgs"
assert_eq "$(systemctl show notify.service -P StatusVarlinkError)" "org.varlink.service.InvalidParameter"

sync_out f
sync_in g

assert_eq "$(systemctl show notify.service -P StatusErrno)" "1"
assert_eq "$(systemctl show notify.service -P StatusBusError)" "org.freedesktop.DBus.Error.InvalidArgs"
assert_eq "$(systemctl show notify.service -P StatusVarlinkError)" "org.varlink.service.InvalidParameter"

sync_out h
sync_in i

assert_eq "$(systemctl show notify.service -p StatusText --value)" "OK"
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "none"

systemctl stop notify.service
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"

# Timeout of READY=1 for Type=notify-reload services (issue #37515)

systemctl start reload-timeout.service

systemctl reload --no-block reload-timeout.service
timeout 10 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "reload-signal" ]]; do sleep .5; done'
sync_in hup1
timeout 10 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "reload-notify" ]]; do sleep .5; done'
timeout 80 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "running" ]]; do sleep 5; done'
assert_eq "$(systemctl show reload-timeout.service -P ReloadResult)" "timeout"

systemctl reload --no-block reload-timeout.service
timeout 10 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "reload-signal" ]]; do sleep .5; done'
assert_eq "$(systemctl show reload-timeout.service -P ReloadResult)" "success"
sync_in hup2
timeout 10 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "reload-notify" ]]; do sleep .5; done'
sync_out ready
timeout 40 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "running" ]]; do sleep 1; done'
assert_eq "$(systemctl show reload-timeout.service -P ReloadResult)" "success"

systemctl reload --no-block reload-timeout.service
sync_in hup3
timeout 40 bash -c 'until [[ $(systemctl show reload-timeout.service -P SubState) == "running" ]]; do sleep 1; done'
assert_eq "$(systemctl show reload-timeout.service -P ReloadResult)" "success"

systemctl stop reload-timeout.service

rm /tmp/syncfifo1 /tmp/syncfifo2

# Explicitly test busctl's BUSERROR= reporting and systemctl status should show it

(! systemd-run --wait --unit="TEST-80-BUSERROR.service" -p NotifyAccess=main busctl introspect org.freedesktop.systemd1 /bogus/001)
assert_eq "$(systemctl show TEST-80-BUSERROR.service -P StatusBusError)" "org.freedesktop.DBus.Error.UnknownObject"
assert_in "D-Bus: org.freedesktop.DBus.Error.UnknownObject" "$(systemctl status TEST-80-BUSERROR.service)"

# Now test basic fdstore behaviour

MYSCRIPT="/tmp/myscript$RANDOM.sh"
cat >> "$MYSCRIPT" <<'EOF'
#!/usr/bin/env bash
set -eux
set -o pipefail
test "$FDSTORE" -eq 7
N="/tmp/$RANDOM"
echo $RANDOM > "$N"
systemd-notify --fd=4 --fdname=quux --pid=parent 4< "$N"
rm "$N"
systemd-notify --ready
exec sleep infinity
EOF

chmod +x "$MYSCRIPT"

MYUNIT="myunit$RANDOM.service"
systemd-run -u "$MYUNIT" -p Type=notify -p FileDescriptorStoreMax=7 "$MYSCRIPT"

test "$(systemd-analyze fdstore "$MYUNIT" | wc -l)" -eq 2
systemd-analyze fdstore "$MYUNIT" --json=short
systemd-analyze fdstore "$MYUNIT" --json=short | grep -P -q '\[{"fdname":"quux","type":.*,"devno":\[.*\],"inode":.*,"rdevno":null,"path":"/tmp/.*","flags":"ro"}\]'

systemctl stop "$MYUNIT"
rm "$MYSCRIPT"

# Test fdstore pinning (this will pull in fdstore-pin.service fdstore-nopin.service)
systemctl start fdstore-pin.target

assert_eq "$(systemctl show fdstore-pin.service -P FileDescriptorStorePreserve)" yes
assert_eq "$(systemctl show fdstore-nopin.service -P FileDescriptorStorePreserve)" restart
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" running
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" running
assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 1

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
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" dead-resources-pinned
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" dead

systemctl start fdstore-pin.service fdstore-nopin.service

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" running
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" running

systemctl stop fdstore-pin.service fdstore-nopin.service

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 1
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" dead-resources-pinned
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" dead

systemctl clean fdstore-pin.service --what=fdstore

assert_eq "$(systemctl show fdstore-pin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-nopin.service -P NFileDescriptorStore)" 0
assert_eq "$(systemctl show fdstore-pin.service -P SubState)" dead
assert_eq "$(systemctl show fdstore-nopin.service -P SubState)" dead

# Test notify-reload signal handler validation

# Test 1: Service without signal handler should start successfully but log a warning
mkfifo /tmp/reload-nohandler-in /tmp/reload-nohandler-out
systemctl start notify-reload-no-handler.service
assert_eq "$(systemctl show notify-reload-no-handler.service -P SubState)" "running"
# Verify warning was logged about missing signal handler
journalctl -u notify-reload-no-handler.service --since=-10s | grep -q "lacks handler for reload signal"
echo "exit" > /tmp/reload-nohandler-in
systemctl stop notify-reload-no-handler.service
rm -f /tmp/reload-nohandler-in /tmp/reload-nohandler-out

# Test 2: Service that removes handler should fail at reload
mkfifo /tmp/reload-toggle-in /tmp/reload-toggle-out
systemctl start notify-reload-toggle-handler.service
assert_eq "$(systemctl show notify-reload-toggle-handler.service -P SubState)" "running"

# Command service to remove its signal handler
echo "remove-handler" > /tmp/reload-toggle-in
read -r response < /tmp/reload-toggle-out
assert_eq "$response" "handler-removed"

# Attempt reload, should fail but service should stay running
(! systemctl reload notify-reload-toggle-handler.service)
assert_eq "$(systemctl show notify-reload-toggle-handler.service -P SubState)" "running"
assert_eq "$(systemctl show notify-reload-toggle-handler.service -P ReloadResult)" "resources"

echo "exit" > /tmp/reload-toggle-in
systemctl stop notify-reload-toggle-handler.service
rm -f /tmp/reload-toggle-in /tmp/reload-toggle-out

# Test 3: Well-behaved service with handler should work correctly
mkfifo /tmp/reload-wellbehaved-in /tmp/reload-wellbehaved-out
systemctl start notify-reload-well-behaved.service
assert_eq "$(systemctl show notify-reload-well-behaved.service -P SubState)" "running"

# Reload should succeed
systemctl reload --no-block notify-reload-well-behaved.service
timeout 10 bash -c 'until [[ $(systemctl show notify-reload-well-behaved.service -P SubState) == "reload-signal" ]]; do sleep .5; done'
read -r response < /tmp/reload-wellbehaved-out
assert_eq "$response" "reload"
timeout 10 bash -c 'until [[ $(systemctl show notify-reload-well-behaved.service -P SubState) == "running" ]]; do sleep .5; done'
assert_eq "$(systemctl show notify-reload-well-behaved.service -P ReloadResult)" "success"

echo "exit" > /tmp/reload-wellbehaved-in
systemctl stop notify-reload-well-behaved.service
rm -f /tmp/reload-wellbehaved-in /tmp/reload-wellbehaved-out

touch /testok
