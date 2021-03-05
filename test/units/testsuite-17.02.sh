#!/usr/bin/env bash
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
ACTION=="remove", GOTO="lo_end"

SUBSYSTEM=="net", KERNEL=="lo", TAG+="systemd", ENV{SYSTEMD_ALIAS}+="/sys/subsystem/net/devices/lo"

ACTION!="change", GOTO="lo_end"

SUBSYSTEM=="net", KERNEL=="lo", ENV{ID_RENAMING}="1"

LABEL="lo_end"
EOF

udevadm control --log-priority=debug --reload --timeout=600
udevadm trigger --action=add --settle /sys/devices/virtual/net/lo
udevadm info /sys/devices/virtual/net/lo
sleep 1
STATE=$(systemctl show --property=ActiveState --value sys-devices-virtual-net-lo.device)
[[ $STATE == "active" ]] || exit 1

udevadm trigger --action=change --settle /sys/devices/virtual/net/lo
udevadm info /sys/devices/virtual/net/lo
sleep 1
STATE=$(systemctl show --property=ActiveState --value sys-devices-virtual-net-lo.device)
[[ $STATE == "inactive" ]] || exit 1

udevadm trigger --action=move --settle /sys/devices/virtual/net/lo
udevadm info /sys/devices/virtual/net/lo
sleep 1
STATE=$(systemctl show --property=ActiveState --value sys-devices-virtual-net-lo.device)
[[ $STATE == "active" ]] || exit 1

rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload --timeout=600

# test for issue #16967

ip link add hoge type dummy
udevadm info --wait-for-initialization=10s /sys/devices/virtual/net/hoge
sleep 1
if ! systemctl status sys-devices-virtual-net-hoge.device; then exit 1; fi
if ! systemctl status sys-subsystem-net-devices-hoge.device; then exit 1; fi

ip link set hoge name foobar
udevadm info --wait-for-initialization=10s /sys/devices/virtual/net/foobar
sleep 1
if systemctl status sys-devices-virtual-net-hoge.device; then exit 1; fi
if systemctl status sys-subsystem-net-devices-hoge.device; then exit 1; fi
if ! systemctl status sys-devices-virtual-net-foobar.device; then exit 1; fi
if ! systemctl status sys-subsystem-net-devices-foobar.device; then exit 1; fi

exit 0
