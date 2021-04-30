#!/usr/bin/env bash
set -ex
set -o pipefail

mkdir -p /run/udev/rules.d/

rm -f /run/udev/rules.d/50-testsuite.rules
udevadm control --reload
udevadm trigger /dev/vda

while : ; do
    (
        udevadm info /dev/vda | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info /dev/vda | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v vda
        systemctl show -p WantedBy waldo.service | grep -q -v vda
    ) && break

    sleep .5
done

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="vda", ENV{SYSTEMD_WANTS}="foobar.service"
EOF
udevadm control --reload
udevadm trigger /dev/vda

while : ; do
    (
        udevadm info /dev/vda | grep -q SYSTEMD_WANTS=foobar.service
        udevadm info /dev/vda | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q vda
        systemctl show -p WantedBy waldo.service | grep -q -v vda
    ) && break

    sleep .5
done

cat >/run/udev/rules.d/50-testsuite.rules <<EOF
ACTION!="remove", SUBSYSTEM=="block", KERNEL=="vda", ENV{SYSTEMD_WANTS}="waldo.service"
EOF
udevadm control --reload
udevadm trigger /dev/vda

while : ; do
    (
        udevadm info /dev/vda | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info /dev/vda | grep -q SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v vda
        systemctl show -p WantedBy waldo.service | grep -q vda
    ) && break

    sleep .5
done

rm /run/udev/rules.d/50-testsuite.rules

udevadm control --reload
udevadm trigger /dev/vda

while : ; do
    (
        udevadm info /dev/vda | grep -q -v SYSTEMD_WANTS=foobar.service
        udevadm info /dev/vda | grep -q -v SYSTEMD_WANTS=waldo.service
        systemctl show -p WantedBy foobar.service | grep -q -v vda
        systemctl show -p WantedBy waldo.service | grep -q -v vda
    ) && break

    sleep .5
done

exit 0
