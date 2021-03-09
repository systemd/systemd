#!/bin/bash
set -ex
set -o pipefail

# tests for udev watch

mkdir -p /run/udev/rules.d/

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
SUBSYSTEM=="block", KERNEL=="sda", OPTIONS="log_level=debug"
ACTION=="add", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="watch"
ACTION=="change", SUBSYSTEM=="block", KERNEL=="sda", OPTIONS:="nowatch"
EOF

udevadm control --reload
udevadm trigger -w -c add /dev/sda

MAJOR=$(udevadm info /dev/sda | grep -e '^E: MAJOR=' | sed -e 's/^E: MAJOR=//')
MINOR=$(udevadm info /dev/sda | grep -e '^E: MINOR=' | sed -e 's/^E: MINOR=//')

test -L /run/udev/watch/b${MAJOR}:${MINOR}
HANDLE=$(readlink /run/udev/watch/b${MAJOR}:${MINOR})
test -L /run/udev/watch/${HANDLE}
test $(readlink /run/udev/watch/${HANDLE}) = "b${MAJOR}:${MINOR}"

systemctl restart systemd-udevd.service

udevadm control --ping

test -L /run/udev/watch/b${MAJOR}:${MINOR}
HANDLE=$(readlink /run/udev/watch/b${MAJOR}:${MINOR})
test -L /run/udev/watch/${HANDLE}
test $(readlink /run/udev/watch/${HANDLE}) = "b${MAJOR}:${MINOR}"

udevadm trigger -w -c change /dev/sda

test ! -e /run/udev/watch/b${MAJOR}:${MINOR}
for i in /run/udev/watch/*; do
    ID_OR_HANDLE=$(readlink $i)
    test -L /run/udev/watch/${ID_OR_HANDLE}
    test $(readlink /run/udev/watch/${ID_OR_HANDLE}) = $(basename $i)
done

# clean up
rm /run/udev/rules.d/50-testsuite.rules
udevadm control --reload
udevadm trigger -w -c change /dev/sda

exit 0
