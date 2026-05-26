#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# disable shellcheck warning about '"aaa"' type quotation
# shellcheck disable=SC2016

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

mkdir -p /run/udev/rules.d/

# test for ID_RENAMING= udev property and device unit state

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="remove", GOTO="hoge_end"
SUBSYSTEM!="net", GOTO="hoge_end"
KERNEL!="hoge", GOTO="hoge_end"

OPTIONS="log_level=debug"

# emulate renaming
ACTION=="online", ENV{ID_RENAMING}="1"

LABEL="hoge_end"
EOF

udevadm control --log-priority=debug --reload --timeout=30

ip link add hoge type dummy
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'

udevadm trigger --action=online --settle /sys/devices/virtual/net/hoge
assert_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "inactive" ]]; do sleep .5; done'

udevadm trigger --action=move --settle /sys/devices/virtual/net/hoge
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'

# test for renaming interface with NAME= (issue #25106)

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="add", GOTO="hoge_end"
SUBSYSTEM!="net", GOTO="hoge_end"

OPTIONS="log_level=debug"

KERNEL=="hoge",  NAME="foobar"
KERNEL=="foobar", NAME="hoge"

LABEL="hoge_end"
EOF

udevadm control --log-priority=debug --reload --timeout=30

udevadm trigger --action=add --settle /sys/devices/virtual/net/hoge
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/foobar
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/foobar)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "active" ]]; do sleep .5; done'

udevadm trigger --action=add --settle /sys/devices/virtual/net/foobar
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge
assert_not_in "ID_RENAMING=" "$(udevadm info /sys/devices/virtual/net/hoge)"
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "inactive" ]]; do sleep .5; done'

# cleanup
rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload --timeout=30

# test for renaming interface with an external tool (issue #16967)

ip link set hoge name foobar
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/foobar
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "active" ]]; do sleep .5; done'

ip link set foobar name hoge
udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/hoge)" != "active" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/devices/virtual/net/foobar)" != "inactive" ]]; do sleep .5; done'
timeout 30 bash -c 'while [[ "$(systemctl show --property=ActiveState --value /sys/subsystem/net/devices/foobar)" != "inactive" ]]; do sleep .5; done'

# cleanup
ip link del hoge

# shellcheck disable=SC2317,SC2329
teardown_netif_renaming_conflict() {
    set +ex

    if [[ -n "$KILL_PID" ]]; then
        kill "$KILL_PID"
    fi

    rm -rf "$TMPDIR"

    rm -f /run/udev/rules.d/50-testsuite.rules
    udevadm control --reload --timeout=30

    ip link del hoge
    ip link del foobar
}

test_netif_renaming_conflict() {
    local since found=

    trap teardown_netif_renaming_conflict RETURN

    cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="add", GOTO="hoge_end"
SUBSYSTEM!="net", GOTO="hoge_end"

OPTIONS="log_level=debug"

KERNEL=="foobar", NAME="hoge"

LABEL="hoge_end"
EOF

    udevadm control --log-priority=debug --reload --timeout=30

    ip link add hoge type dummy
    udevadm wait --timeout=30 --settle /sys/devices/virtual/net/hoge

    TMPDIR=$(mktemp -d -p /tmp udev-tests.XXXXXX)
    udevadm monitor --udev --property --subsystem-match=net >"$TMPDIR"/monitor.txt &
    KILL_PID="$!"

    # make sure that 'udevadm monitor' actually monitor uevents
    sleep 1

    journalctl --sync
    since="$(date '+%H:%M:%S')"

    # add another interface which will conflict with an existing interface
    ip link add foobar type dummy

    for _ in {1..40}; do
        if (
            grep -q 'ACTION=add' "$TMPDIR"/monitor.txt
            grep -q 'DEVPATH=/devices/virtual/net/foobar' "$TMPDIR"/monitor.txt
            grep -q 'SUBSYSTEM=net' "$TMPDIR"/monitor.txt
            grep -q 'INTERFACE=foobar' "$TMPDIR"/monitor.txt
            grep -q 'ID_NET_DRIVER=dummy' "$TMPDIR"/monitor.txt
            grep -q 'ID_NET_NAME=foobar' "$TMPDIR"/monitor.txt
            # Even when network interface renaming is failed, SYSTEMD_ALIAS with the conflicting name will be broadcast.
            grep -q 'SYSTEMD_ALIAS=/sys/subsystem/net/devices/hoge' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_FAILED=1' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_ERRNO=17' "$TMPDIR"/monitor.txt
            grep -q 'UDEV_WORKER_ERRNO_NAME=EEXIST' "$TMPDIR"/monitor.txt
        ); then
            cat "$TMPDIR"/monitor.txt
            found=1
            break
        fi
        sleep .5
    done
    test -n "$found"

    journalctl --sync
    timeout -v 30 bash -c "journalctl _PID=1 _COMM=systemd --since '$since' -n all --follow | grep -m 1 -q -F 'foobar: systemd-udevd failed to process the device, ignoring: File exists'"
    # check if the invalid SYSTEMD_ALIAS property for the interface foobar is ignored by PID1
    assert_eq "$(systemctl show --property=SysFSPath --value /sys/subsystem/net/devices/hoge)" "/sys/devices/virtual/net/hoge"
}

test_netif_renaming_conflict

# shellcheck disable=SC2317,SC2329
teardown_netif_renaming_keeps_properties() {
    set +ex

    rm -f /run/udev/rules.d/50-testsuite.rules
    udevadm control --reload --timeout=30

    ip link del rename-src 2>/dev/null || :
    ip link del rename-dst 2>/dev/null || :
}

test_netif_renaming_keeps_properties() {
    trap teardown_netif_renaming_keeps_properties RETURN

    cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="add", GOTO="end"
SUBSYSTEM!="net", GOTO="end"

OPTIONS="log_level=debug"

# Set properties before, during, and after a rename to a name that is already
# taken. The rename will fail with -EEXIST, but the property assignments must
# persist.
KERNEL=="rename-src", ENV{ID_TEST_PROP_BEFORE}="before"
KERNEL=="rename-src", ENV{ID_TEST_PROP_DURING}="during", NAME="rename-dst"
KERNEL=="rename-src", ENV{ID_TEST_PROP_AFTER}="after"

LABEL="end"
EOF

    udevadm control --log-priority=debug --reload --timeout=30

    # Pre-create the conflicting target so the rename is guaranteed to fail.
    ip link add rename-dst type dummy
    udevadm wait --timeout=30 --settle /sys/devices/virtual/net/rename-dst

    ip link add rename-src type dummy
    udevadm wait --timeout=30 --settle /sys/devices/virtual/net/rename-src

    # Sanity check: the rename did fail and the original interface still exists.
    [[ -d /sys/devices/virtual/net/rename-src ]]

    # The properties set by the rule alongside NAME= must be present in the udev
    # database even though the rename itself failed. Check one assigned before,
    # one assigned on the same line as the failing NAME= token, and one
    # assigned after.
    info="$(udevadm info /sys/devices/virtual/net/rename-src)"
    assert_in "ID_TEST_PROP_BEFORE=before" "$info"
    assert_in "ID_TEST_PROP_DURING=during" "$info"
    assert_in "ID_TEST_PROP_AFTER=after" "$info"
}

test_netif_renaming_keeps_properties

exit 0
