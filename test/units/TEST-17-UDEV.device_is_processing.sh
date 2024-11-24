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
    # Forcibly kills sleep command invoked by the udev rule before restarting,
    # otherwise systemctl restart below will takes longer.
    killall -KILL sleep
    systemctl restart systemd-udevd.service
    ip link del "$IFNAME"
}

trap at_exit EXIT

udevadm settle

mkdir -p /run/udev/udev.conf.d/
cat >/run/udev/udev.conf.d/timeout.conf <<EOF
event_timeout=1h
EOF

mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/99-testsuite.rules <<EOF
SUBSYSTEM=="net", ACTION=="change", KERNEL=="${IFNAME}", OPTIONS="log_level=debug", RUN+="/usr/bin/sleep 1000"
EOF

systemctl restart systemd-udevd.service

ip link add "$IFNAME" type dummy
IFINDEX=$(ip -json link show "$IFNAME" | jq '.[].ifindex')
udevadm wait --timeout 10 "/sys/class/net/${IFNAME}"
# Check if the database file is created.
[[ -e "/run/udev/data/n${IFINDEX}" ]]

systemd-run \
    -p After="sys-subsystem-net-devices-${IFNAME}.device" \
    -p BindsTo="sys-subsystem-net-devices-${IFNAME}.device" \
    -u testsleep.service \
    sleep 1h

timeout 10 bash -c 'until systemctl is-active testsleep.service; do sleep .5; done'

udevadm trigger "/sys/class/net/${IFNAME}"
timeout 30 bash -c "until grep -F 'ID_PROCESSING=1' /run/udev/data/n${IFINDEX}; do sleep .5; done"

for _ in {1..3}; do
    systemctl daemon-reexec
    systemctl is-active testsleep.service
done

for _ in {1..3}; do
    systemctl daemon-reload
    systemctl is-active testsleep.service
done

# Check if the reexec and reload have finished during processing the event.
grep -F 'ID_PROCESSING=1' "/run/udev/data/n${IFINDEX}"

exit 0
