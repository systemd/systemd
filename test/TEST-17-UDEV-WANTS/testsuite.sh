#!/bin/bash
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload
udevadm trigger /dev/sda

while : ; do
    (
        udevadm info /dev/sda | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info /dev/sda | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v sda
        systemctl show -p WantedBy waldo.service | grep -q -v sda
    ) && break

    sleep .5
done

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="sda", ENV{SYSTEMD_WANTS}="foobar.service"
EOF
udevadm control --reload
udevadm trigger /dev/sda

while : ; do
    (
        udevadm info /dev/sda | grep -q SYSTEMD_WANTS=foobar.service
        udevadm info /dev/sda | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q sda
        systemctl show -p WantedBy waldo.service | grep -q -v sda
    ) && break

    sleep .5
done

cat > /run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="sda", ENV{SYSTEMD_WANTS}="waldo.service"
EOF
udevadm control --reload
udevadm trigger /dev/sda

while : ; do
    (
        udevadm info /dev/sda | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info /dev/sda | grep -q SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v sda
        systemctl show -p WantedBy waldo.service | grep -q sda
    ) && break

    sleep .5
done

rm /run/udev/rules.d/50-testsuite.rules

udevadm control --reload
udevadm trigger /dev/sda

while : ; do
    (
        udevadm info /dev/sda | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info /dev/sda | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v sda
        systemctl show -p WantedBy waldo.service | grep -q -v sda
    ) && break

    sleep .5
done

echo OK > /testok

exit 0
