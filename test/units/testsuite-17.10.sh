#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Coverage test for udevadm

# shellcheck disable=SC2317
cleanup_17_10() {
    set +e

    losetup -d "$loopdev"
    rm -f "$blk"

    ip link delete "$netdev"
}

# Set up some test devices
trap cleanup_17_10 EXIT

netdev=dummy17.10
ip link add $netdev type dummy

blk="$(mktemp)"
dd if=/dev/zero of="$blk" bs=1M count=1
loopdev="$(losetup --show -f "$blk")"

udevadm -h

udevadm control -e
udevadm control -l emerg
udevadm control -l alert
udevadm control -l crit
udevadm control -l err
udevadm control -l warning
udevadm control -l notice
udevadm control --log-level info
udevadm control --log-level debug
(! udevadm control -l hello)
udevadm control -s
udevadm control -S
udevadm control -R
udevadm control -p HELLO=world
udevadm control -m 42
udevadm control --ping
udevadm control -t 5
udevadm control -h

udevadm info /dev/null
udevadm info /sys/class/net/$netdev
udevadm info "$(systemd-escape -p --suffix device /sys/devices/virtual/net/$netdev)"
udevadm info --property DEVNAME /sys/class/net/$netdev
udevadm info --property DEVNAME --value /sys/class/net/$netdev
udevadm info --property HELLO /sys/class/net/$netdev
udevadm info -p class/net/$netdev
udevadm info -p /class/net/$netdev
udevadm info --json=off -p class/net/$netdev
udevadm info --json=pretty -p class/net/$netdev | jq .
udevadm info --json=short -p class/net/$netdev | jq .
udevadm info -n null
udevadm info -q all /sys/class/net/$netdev
udevadm info -q name /dev/null
udevadm info -q path /sys/class/net/$netdev
udevadm info -q property /sys/class/net/$netdev
udevadm info -q symlink /sys/class/net/$netdev
udevadm info -q name -r /dev/null
udevadm info --query symlink --root /sys/class/net/$netdev
(! udevadm info -q hello -r /sys/class/net/$netdev)
udevadm info -a /sys/class/net/$netdev
udevadm info -t >/dev/null
udevadm info --tree /sys/class/net/$netdev
udevadm info -x /sys/class/net/$netdev
udevadm info -x -q path /sys/class/net/$netdev
udevadm info -P TEST_ /sys/class/net/$netdev
udevadm info -d /dev/null
udevadm info -e >/dev/null
udevadm info -e --json=off >/dev/null
udevadm info -e --json=pretty | jq . >/dev/null
udevadm info -e --json=short | jq . >/dev/null
udevadm info -e --subsystem-match acpi >/dev/null
udevadm info -e --subsystem-nomatch acpi >/dev/null
udevadm info -e --attr-match ifindex=2 >/dev/null
udevadm info -e --attr-nomatch ifindex=2 >/dev/null
udevadm info -e --property-match SUBSYSTEM=acpi >/dev/null
udevadm info -e --tag-match systemd >/dev/null
udevadm info -e --sysname-match lo >/dev/null
udevadm info -e --name-match /sys/class/net/$netdev >/dev/null
udevadm info -e --parent-match /sys/class/net/$netdev >/dev/null
udevadm info -e --initialized-match >/dev/null
udevadm info -e --initialized-nomatch >/dev/null
# udevadm info -c
udevadm info -w /sys/class/net/$netdev
udevadm info --wait-for-initialization=5 /sys/class/net/$netdev
udevadm info -h

assert_rc 124 timeout 1 udevadm monitor
assert_rc 124 timeout 1 udevadm monitor -k
assert_rc 124 timeout 1 udevadm monitor -u
assert_rc 124 timeout 1 udevadm monitor -s net
assert_rc 124 timeout 1 udevadm monitor --subsystem-match net/$netdev
assert_rc 124 timeout 1 udevadm monitor -t systemd
assert_rc 124 timeout 1 udevadm monitor --tag-match hello
udevadm monitor -h

udevadm settle
udevadm settle -t 5
udevadm settle -E /sys/class/net/$netdev
udevadm settle -h

udevadm test /dev/null
udevadm info /sys/class/net/$netdev
udevadm test "$(systemd-escape -p --suffix device /sys/devices/virtual/net/$netdev)"
udevadm test -a add /sys/class/net/$netdev
udevadm test -a change /sys/class/net/$netdev
udevadm test -a move /sys/class/net/$netdev
udevadm test -a online /sys/class/net/$netdev
udevadm test -a offline /sys/class/net/$netdev
udevadm test -a bind /sys/class/net/$netdev
udevadm test -a unbind /sys/class/net/$netdev
udevadm test -a help /sys/class/net/$netdev
udevadm test --action help
(! udevadm test -a hello /sys/class/net/$netdev)
udevadm test -N early /sys/class/net/$netdev
udevadm test -N late /sys/class/net/$netdev
udevadm test --resolve-names never /sys/class/net/$netdev
(! udevadm test -N hello /sys/class/net/$netdev)
udevadm test -h

# udevadm test-builtin path_id "$loopdev"
udevadm test-builtin net_id /sys/class/net/$netdev
udevadm test-builtin net_id "$(systemd-escape -p --suffix device /sys/devices/virtual/net/$netdev)"
udevadm test-builtin -a add net_id /sys/class/net/$netdev
udevadm test-builtin -a remove net_id /sys/class/net/$netdev
udevadm test-builtin -a change net_id /sys/class/net/$netdev
udevadm test-builtin -a move net_id /sys/class/net/$netdev
udevadm test-builtin -a online net_id /sys/class/net/$netdev
udevadm test-builtin -a offline net_id /sys/class/net/$netdev
udevadm test-builtin -a bind net_id /sys/class/net/$netdev
udevadm test-builtin -a unbind net_id /sys/class/net/$netdev
udevadm test-builtin -a help net_id /sys/class/net/$netdev
udevadm test-builtin net_setup_link /sys/class/net/$netdev
udevadm test-builtin blkid "$loopdev"
udevadm test-builtin input_id /sys/class/net/$netdev
udevadm test-builtin keyboard /dev/null
# udevadm test-builtin kmod /sys/class/net/$netdev
udevadm test-builtin uaccess /dev/null
# udevadm test-builtin usb_id dev/null
(! udevadm test-builtin hello /sys/class/net/$netdev)
# systemd-hwdb update is extremely slow when combined with sanitizers and run
# in a VM without acceleration, so let's just skip the one particular test
# if we detect this combination
if ! [[ -v ASAN_OPTIONS && "$(systemd-detect-virt -v)" == "qemu" ]]; then
    modprobe scsi_debug
    scsidev=$(readlink -f /sys/bus/pseudo/drivers/scsi_debug/adapter*/host*/target*/[0-9]*)
    mkdir -p /etc/udev/hwdb.d
    cat >/etc/udev/hwdb.d/99-test.hwdb <<EOF
scsi:*
  ID_TEST=test
EOF
    systemd-hwdb update

    udevadm test-builtin hwdb "$scsidev"

    rmmod scsi_debug || :
    rm -fv /etc/udev/hwdb.d/99-test.hwdb
    systemd-hwdb update
fi


udevadm trigger
udevadm trigger /dev/null
udevadm trigger /sys/class/net/$netdev
udevadm trigger "$(systemd-escape -p --suffix device /sys/devices/virtual/net/$netdev)"
udevadm trigger -v /sys/class/net/$netdev
udevadm trigger -n /sys/class/net/$netdev
udevadm trigger -q /sys/class/net/$netdev
udevadm trigger -t all /sys/class/net/$netdev
udevadm trigger -t devices /sys/class/net/$netdev
udevadm trigger --type subsystems /sys/class/net/$netdev
(! udevadm trigger -t hello /sys/class/net/$netdev)
udevadm trigger -c add /sys/class/net/$netdev
udevadm trigger -c remove /sys/class/net/$netdev
udevadm trigger -c change /sys/class/net/$netdev
udevadm trigger -c move /sys/class/net/$netdev
udevadm trigger -c online /sys/class/net/$netdev
udevadm trigger -c offline /sys/class/net/$netdev
udevadm trigger -c bind /sys/class/net/$netdev
udevadm trigger -c unbind /sys/class/net/$netdev
udevadm trigger -c help /sys/class/net/$netdev
udevadm trigger --action help /sys/class/net/$netdev
(! udevadm trigger -c hello /sys/class/net/$netdev)
udevadm trigger --prioritized-subsystem block
udevadm trigger --prioritized-subsystem block,net
udevadm trigger --prioritized-subsystem hello
udevadm trigger -s net
udevadm trigger -S net
udevadm trigger -a subsystem=net
udevadm trigger --attr-match hello=world
udevadm trigger -p DEVNAME=null
udevadm trigger --property-match HELLO=world
udevadm trigger -g systemd
udevadm trigger --tag-match hello
udevadm trigger -y net
udevadm trigger --sysname-match hello
udevadm trigger --name-match /sys/class/net/$netdev
udevadm trigger --name-match /sys/class/net/$netdev --name-match /dev/null
udevadm trigger -b /sys/class/net/$netdev
udevadm trigger --parent-match /sys/class/net/$netdev --name-match /dev/null
udevadm trigger --initialized-match
udevadm trigger --initialized-nomatch
udevadm trigger -w
udevadm trigger --uuid /sys/class/net/$netdev
udevadm settle -t 300
udevadm trigger --wait-daemon
udevadm settle -t 300
udevadm trigger --wait-daemon=5
udevadm trigger -h

# https://github.com/systemd/systemd/issues/29863
if [[ "$(systemd-detect-virt -v)" != "qemu" ]]; then
    udevadm control --log-level=0
    for _ in {0..9}; do
        timeout 30 udevadm trigger --settle
    done
    udevadm control --log-level=debug
fi

udevadm wait /dev/null
udevadm wait /sys/class/net/$netdev
udevadm wait -t 5 /sys/class/net/$netdev
udevadm wait --initialized true /sys/class/net/$netdev
udevadm wait --initialized false /sys/class/net/$netdev
(! udevadm wait --initialized hello /sys/class/net/$netdev)
assert_rc 124 timeout 5 udevadm wait --removed /sys/class/net/$netdev
udevadm wait --settle /sys/class/net/$netdev
udevadm wait -h

udevadm lock --help
udevadm lock --version
for i in /dev/block/*; do
    udevadm lock --device "$i" --print
    udevadm lock --device "$i" true
    (! udevadm lock --device "$i" false)
done
for i in / /usr; do
    udevadm lock --backing "$i" --print
    udevadm lock --backing "$i" true
    (! udevadm lock --backing "$i" false)
done

exit 0
