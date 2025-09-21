#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

at_exit() {
    set +e
    rm -rf /var/lib/machines/mymachine.raw.v
    rm -rf /var/lib/machines/mytree.v
    rm -rf /var/lib/machines/testroot.v
    umount -l /tmp/dotvroot
    rmdir /tmp/dotvroot
}

trap at_exit EXIT

mkdir -p /var/lib/machines/mymachine.raw.v

touch /var/lib/machines/mymachine.raw.v/mymachine_7.5.13.raw
touch /var/lib/machines/mymachine.raw.v/mymachine_7.5.14_x86-64.raw
touch /var/lib/machines/mymachine.raw.v/mymachine_7.6.0_arm64.raw
touch /var/lib/machines/mymachine.raw.v/mymachine_7.7.0_x86-64+0-5.raw

mkdir -p /var/lib/machines/mytree.v

mkdir /var/lib/machines/mytree.v/mytree_33.4
mkdir /var/lib/machines/mytree.v/mytree_33.5
mkdir /var/lib/machines/mytree.v/mytree_36.0+0-5
mkdir /var/lib/machines/mytree.v/mytree_37.0_arm64+2-3
mkdir /var/lib/machines/mytree.v/mytree_38.0_arm64+0-5

ARCH="$(busctl get-property org.freedesktop.systemd1 /org/freedesktop/systemd1 org.freedesktop.systemd1.Manager Architecture | cut -d\" -f 2)"

export SYSTEMD_LOG_LEVEL=debug

if [ "$ARCH" = "x86-64" ] ; then
    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.14_x86-64.raw"

    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.5.13)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.13.raw"
    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.5.14)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.14_x86-64.raw"
    (! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.6.0)
    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.7.0)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.7.0_x86-64+0-5.raw"

    systemd-dissect --discover | grep "/var/lib/machines/mymachine.raw.v/mymachine_7.5.14_x86-64.raw"
elif [ "$ARCH" = "arm64" ] ; then
    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.6.0_arm64.raw"

    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.5.13)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.13.raw"
    (! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.5.14)
    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.6.0)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.6.0_arm64.raw"
    (! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.7.0)

    systemd-dissect --discover | grep "/var/lib/machines/mymachine.raw.v/mymachine_7.6.0_arm64.raw"
else
    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.13.raw"

    test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.5.13)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.13.raw"
    (! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.5.14)
    (! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.6.0)
    (! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -V 7.7.0)

    systemd-dissect --discover | grep "/var/lib/machines/mymachine.raw.v/mymachine_7.5.13.raw"
fi

test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A x86-64)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.5.14_x86-64.raw"
test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.6.0_arm64.raw"
(! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A ia64)

test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -p version)" = "7.6.0"
test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -p type)" = "reg"
test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -p filename)" = "mymachine_7.6.0_arm64.raw"
test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -p arch)" = "arm64"

test "$(systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -t reg)" = "/var/lib/machines/mymachine.raw.v/mymachine_7.6.0_arm64.raw"
(! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -t dir)
(! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -t fifo)
(! systemd-vpick /var/lib/machines/mymachine.raw.v --suffix=.raw -A arm64 -t sock)

if [ "$ARCH" != "arm64" ] ; then
    test "$(systemd-vpick /var/lib/machines/mytree.v)" = "/var/lib/machines/mytree.v/mytree_33.5/"
    test "$(systemd-vpick /var/lib/machines/mytree.v --type=dir)" = "/var/lib/machines/mytree.v/mytree_33.5/"
else
    test "$(systemd-vpick /var/lib/machines/mytree.v)" = "/var/lib/machines/mytree.v/mytree_37.0_arm64+2-3/"
    test "$(systemd-vpick /var/lib/machines/mytree.v --type=dir)" = "/var/lib/machines/mytree.v/mytree_37.0_arm64+2-3/"
fi

(! systemd-vpick /var/lib/machines/mytree.v --type=reg)

mkdir /tmp/dotvroot
mount --bind / /tmp/dotvroot

mkdir /var/lib/machines/testroot.v
mkdir /var/lib/machines/testroot.v/testroot_32
ln -s /tmp/dotvroot /var/lib/machines/testroot.v/testroot_33
mkdir /var/lib/machines/testroot.v/testroot_34

ls -l /var/lib/machines/testroot.v

test "$(systemd-vpick /var/lib/machines/testroot.v)" = /var/lib/machines/testroot.v/testroot_34/
test "$(systemd-vpick --resolve=yes /var/lib/machines/testroot.v)" = /var/lib/machines/testroot.v/testroot_34/
(! systemd-run --wait -p RootDirectory=/var/lib/machines/testroot.v true)

find /var/lib/machines/testroot.v/testroot_34
rm -rf /var/lib/machines/testroot.v/testroot_34
test "$(systemd-vpick /var/lib/machines/testroot.v)" = /var/lib/machines/testroot.v/testroot_33/
test "$(systemd-vpick --resolve=yes /var/lib/machines/testroot.v)" = /tmp/dotvroot/
systemd-run --wait -p RootDirectory=/var/lib/machines/testroot.v true

rm /var/lib/machines/testroot.v/testroot_33
test "$(systemd-vpick /var/lib/machines/testroot.v)" = /var/lib/machines/testroot.v/testroot_32/
test "$(systemd-vpick --resolve=yes /var/lib/machines/testroot.v)" = /var/lib/machines/testroot.v/testroot_32/
(! systemd-run --wait -p RootDirectory=/var/lib/machines/testroot.v true)

rm -rf /var/lib/machines/testroot.v/testroot_32
(! systemd-vpick /var/lib/machines/testroot.v)
(! systemd-run --wait -p RootDirectory=/var/lib/machines/testroot.v true)
