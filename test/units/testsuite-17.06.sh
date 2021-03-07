#!/bin/bash
set -ex
set -o pipefail

# tests for udev watch

function check_validity() {
    for i in /run/udev/watch/*; do
        ID_OR_HANDLE=$(readlink $i)
        test -L /run/udev/watch/${ID_OR_HANDLE}
        test $(readlink /run/udev/watch/${ID_OR_HANDLE}) = $(basename $i)
    done
}

mkdir -p /run/udev/rules.d/

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="block", KERNEL=="sda", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="watch"
ACTION=="change", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="nowatch"
EOF

udevadm control --reload
udevadm trigger -w -c add /dev/sda
udevadm settle

MAJOR=$(udevadm info /dev/sda | grep -e '^E: MAJOR=' | sed -e 's/^E: MAJOR=//')
MINOR=$(udevadm info /dev/sda | grep -e '^E: MINOR=' | sed -e 's/^E: MINOR=//')

test -L /run/udev/watch/b${MAJOR}:${MINOR}
check_validity

systemctl restart systemd-udevd.service

udevadm control --ping
udevadm settle

test -L /run/udev/watch/b${MAJOR}:${MINOR}
check_validity

udevadm trigger -w -c change /dev/sda
udevadm settle

test ! -e /run/udev/watch/b${MAJOR}:${MINOR}
check_validity

# clean up
rm /run/udev/rules.d/50-testsuite.rules
udevadm control --reload
udevadm trigger -w -c change /dev/sda
udevadm settle

exit 0
