#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

wait_service_active() {(
    set +ex
    for i in {1..20}; do
        (( i > 1 )) && sleep 0.5
        if systemctl --quiet is-active "${1?}"; then
            return 0
        fi
    done
    return 1
)}

wait_service_inactive() {(
    set +ex
    for i in {1..20}; do
        (( i > 1 )) && sleep 0.5
        systemctl --quiet is-active "${1?}"
        if [[ "$?" == "3" ]]; then
            return 0
        fi
    done
    return 1
)}

mkdir -p /run/systemd/system
cat >/run/systemd/system/both.service <<EOF
[Service]
ExecStart=sleep 1000
EOF

cat >/run/systemd/system/on-add.service <<EOF
[Service]
ExecStart=sleep 1000
EOF

cat >/run/systemd/system/on-change.service <<EOF
[Service]
ExecStart=sleep 1000
EOF

systemctl daemon-reload

mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="net", KERNEL=="dummy9?", OPTIONS="log_level=debug"
SUBSYSTEM=="net", KERNEL=="dummy9?", ACTION=="add",    TAG+="systemd", ENV{SYSTEMD_WANTS}+="both.service", ENV{SYSTEMD_WANTS}+="on-add.service"
SUBSYSTEM=="net", KERNEL=="dummy9?", ACTION=="change", TAG+="systemd", ENV{SYSTEMD_WANTS}+="both.service", ENV{SYSTEMD_WANTS}+="on-change.service"
EOF

udevadm control --reload

# StopWhenUnneeded=no
ip link add dummy99 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy99
wait_service_active both.service
wait_service_active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service
systemctl stop both.service on-add.service

udevadm trigger --action=change --settle /sys/class/net/dummy99
udevadm info /sys/class/net/dummy99
wait_service_active both.service
assert_rc 3 systemctl --quiet is-active on-add.service
wait_service_active on-change.service
systemctl stop both.service on-change.service

ip link del dummy99
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy99
assert_rc 3 systemctl --quiet is-active both.service
assert_rc 3 systemctl --quiet is-active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

# StopWhenUnneeded=yes
cat >/run/systemd/system/both.service <<EOF
[Unit]
StopWhenUnneeded=yes

[Service]
ExecStart=sleep 1000
Type=simple
EOF

cat >/run/systemd/system/on-add.service <<EOF
[Unit]
StopWhenUnneeded=yes

[Service]
ExecStart=sleep 1000
Type=simple
EOF

cat >/run/systemd/system/on-change.service <<EOF
[Unit]
StopWhenUnneeded=yes

[Service]
ExecStart=echo changed
RemainAfterExit=true
Type=oneshot
EOF

systemctl daemon-reload

# StopWhenUnneeded=yes (single device, only add event)
ip link add dummy99 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy99
wait_service_active both.service
wait_service_active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

ip link del dummy99
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy99
wait_service_inactive both.service
wait_service_inactive on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

# StopWhenUnneeded=yes (single device, add and change event)
ip link add dummy99 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy99
wait_service_active both.service
wait_service_active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

udevadm trigger --action=change --settle /sys/class/net/dummy99
assert_rc 0 systemctl --quiet is-active both.service
wait_service_inactive on-add.service
wait_service_active on-change.service

ip link del dummy99
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy99
wait_service_inactive both.service
assert_rc 3 systemctl --quiet is-active on-add.service
wait_service_inactive on-change.service

# StopWhenUnneeded=yes (multiple devices, only add events)
ip link add dummy99 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy99
wait_service_active both.service
wait_service_active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

ip link add dummy98 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy98
assert_rc 0 systemctl --quiet is-active both.service
assert_rc 0 systemctl --quiet is-active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

ip link del dummy99
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy99
assert_rc 0 systemctl --quiet is-active both.service
assert_rc 0 systemctl --quiet is-active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

ip link del dummy98
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy98
wait_service_inactive both.service
wait_service_inactive on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

# StopWhenUnneeded=yes (multiple devices, add and change events)
ip link add dummy99 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy99
wait_service_active both.service
wait_service_active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

ip link add dummy98 type dummy
udevadm wait --settle --timeout=30 /sys/class/net/dummy98
assert_rc 0 systemctl --quiet is-active both.service
assert_rc 0 systemctl --quiet is-active on-add.service
assert_rc 3 systemctl --quiet is-active on-change.service

udevadm trigger --action=change --settle /sys/class/net/dummy99
assert_rc 0 systemctl --quiet is-active both.service
assert_rc 0 systemctl --quiet is-active on-add.service
wait_service_active on-change.service

ip link del dummy98
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy98
assert_rc 0 systemctl --quiet is-active both.service
wait_service_inactive on-add.service
assert_rc 0 systemctl --quiet is-active on-change.service

ip link del dummy99
udevadm wait --settle --timeout=30 --removed /sys/class/net/dummy99
wait_service_inactive both.service
assert_rc 3 systemctl --quiet is-active on-add.service
wait_service_inactive on-change.service

# cleanup
rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload

rm -f /run/systemd/system/on-add.service
rm -f /run/systemd/system/on-change.service
systemctl daemon-reload

exit 0
