#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2317
set -ex
set -o pipefail

# This is a reproducer of issue #35329,
# which is a regression caused by 405be62f05d76f1845f347737b5972158c79dd3e.

IFNAME=udevtestnetif

at_exit() {
    set +e

    systemctl stop testsleep.service
    rm -f /run/udev/udev.conf.d/timeout.conf
    rm -f /run/udev/rules.d/99-testsuite.rules
    pkill -f '(/usr/bin/)?sleep'
    udevadm control --reload
    ip link del "$IFNAME"
}

trap at_exit EXIT

udevadm settle --timeout=30

mkdir -p /run/udev/udev.conf.d/
cat >/run/udev/udev.conf.d/timeout.conf <<EOF
event_timeout=1h
EOF

# First, test 'add' event.
mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/99-testsuite.rules <<EOF
SUBSYSTEM=="net", ACTION=="add", KERNEL=="${IFNAME}", OPTIONS="log_level=debug", RUN+="/usr/bin/sleep 1000"
EOF

udevadm control --reload

ip link add "$IFNAME" type dummy
IFINDEX=$(ip -json link show "$IFNAME" | jq '.[].ifindex')
timeout 30 bash -c "until [[ -e /run/udev/data/n${IFINDEX} ]] && grep -q -F 'ID_PROCESSING=1' /run/udev/data/n${IFINDEX}; do sleep .5; done"

(! systemctl is-active "sys-devices-virtual-net-${IFNAME}.device")
(! systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device")

for _ in {1..3}; do
    systemctl daemon-reexec
    (! systemctl is-active "sys-devices-virtual-net-${IFNAME}.device")
    (! systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device")
done

for _ in {1..3}; do
    systemctl daemon-reload
    (! systemctl is-active "sys-devices-virtual-net-${IFNAME}.device")
    (! systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device")
done

# Check if the reexec and reload have finished during processing the event.
grep -q -F 'ID_PROCESSING=1' "/run/udev/data/n${IFINDEX}"

# Forcibly kill sleep command invoked by the udev rule to finish processing the add event.
pkill -f '(/usr/bin/)?sleep'
udevadm settle --timeout=30

# Check if ID_PROCESSING flag is unset, and the device units are active.
(! grep -q -F 'ID_PROCESSING=1' "/run/udev/data/n${IFINDEX}")
systemctl is-active "sys-devices-virtual-net-${IFNAME}.device"
systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device"

# Next, test 'change' event.
cat >/run/udev/rules.d/99-testsuite.rules <<EOF
SUBSYSTEM=="net", ACTION=="change", KERNEL=="${IFNAME}", OPTIONS="log_level=debug", RUN+="/usr/bin/sleep 1000"
EOF
udevadm control --reload

systemd-run \
    -p After="sys-subsystem-net-devices-${IFNAME}.device" \
    -p BindsTo="sys-subsystem-net-devices-${IFNAME}.device" \
    -u testsleep.service \
    sleep 1h

udevadm trigger "/sys/class/net/${IFNAME}"
timeout 30 bash -c "until grep -q -F 'ID_PROCESSING=1' /run/udev/data/n${IFINDEX}; do sleep .5; done"

# Check if the service and device units are still active even ID_PROCESSING flag is set.
systemctl is-active testsleep.service
systemctl is-active "sys-devices-virtual-net-${IFNAME}.device"
systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device"

for _ in {1..3}; do
    systemctl daemon-reexec
    systemctl is-active testsleep.service
    systemctl is-active "sys-devices-virtual-net-${IFNAME}.device"
    systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device"
done

for _ in {1..3}; do
    systemctl daemon-reload
    systemctl is-active testsleep.service
    systemctl is-active "sys-devices-virtual-net-${IFNAME}.device"
    systemctl is-active "sys-subsystem-net-devices-${IFNAME}.device"
done

# Check if the reexec and reload have finished during processing the event.
grep -q -F 'ID_PROCESSING=1' "/run/udev/data/n${IFINDEX}"

exit 0
