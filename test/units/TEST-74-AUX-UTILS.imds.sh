#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh


if ! test -x /usr/lib/systemd/systemd-imdsd ; then
    echo "No imdsd installed, skipping test."
    exit 0
fi

at_exit() {
    set +e
    systemctl stop fake-imds systemd-imdsd.socket ||:
    ip link del dummy1 2>/dev/null ||:
    ip link del dummy0 2>/dev/null ||:
    rm -f /run/credstore/firstboot.hostname \
          /run/credstore/acredtest \
          /run/systemd/system/systemd-imdsd@.service.d/50-env.conf \
          /run/systemd/system/systemd-imdsd@.service.d/50-multi-interface.conf
    rmdir /run/systemd/system/systemd-imdsd@.service.d 2>/dev/null ||:
}

trap at_exit EXIT

systemd-run -p Type=notify --unit=fake-imds /usr/lib/systemd/tests/integration-tests/TEST-74-AUX-UTILS/TEST-74-AUX-UTILS.units/fake-imds.py
systemctl status fake-imds

ip link add dummy0 type dummy
ip link set dummy0 up
ip addr add 192.168.47.11/24 dev dummy0

USERDATA='{"systemd.credentials":[{"name":"acredtest","text":"avalue"}]}'

IMDSD="/usr/lib/systemd/systemd-imdsd --vendor=test --data-url=http://192.168.47.11:8088 --well-known-key=userdata:/userdata --well-known-key=hostname:/hostname"
assert_eq "$($IMDSD --well-known=hostname)" "piff"
assert_eq "$($IMDSD --well-known=userdata)" "$USERDATA"
assert_eq "$($IMDSD /hostname)" "piff"
assert_eq "$($IMDSD /userdata)" "$USERDATA"

mkdir -p /run/systemd/system/systemd-imdsd@.service.d/
cat >/run/systemd/system/systemd-imdsd@.service.d/50-env.conf <<EOF
[Service]
Environment=SYSTEMD_IMDS_VENDOR=test2
Environment=SYSTEMD_IMDS_DATA_URL=http://192.168.47.11:8088
Environment=SYSTEMD_IMDS_KEY_USERDATA=/userdata
Environment=SYSTEMD_IMDS_KEY_HOSTNAME=/hostname
EOF
systemctl daemon-reload
systemctl start systemd-imdsd.socket

assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"
assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=userdata)" "$USERDATA"
assert_eq "$(/usr/lib/systemd/systemd-imds -u)" "$USERDATA"

/usr/lib/systemd/systemd-imds
/usr/lib/systemd/systemd-imds --import

assert_eq "$(cat /run/credstore/firstboot.hostname)" "piff"
assert_eq "$(cat /run/credstore/acredtest)" "avalue"

assert_eq "$(/usr/lib/systemd/systemd-imds --interface=dummy0 --well-known=hostname)" "piff"
assert_eq "$(/usr/lib/systemd/systemd-imds -I dummy0 --well-known=hostname)" "piff"
assert_eq "$(/usr/lib/systemd/systemd-imds --interface=dummy0 --well-known=userdata)" "$USERDATA"

assert_fail /usr/lib/systemd/systemd-imds --interface=doesnotexist999 --well-known=hostname

ip link add dummy1 type dummy
ip link set dummy1 up
ip addr add 192.168.47.12/24 dev dummy1

cat >/run/systemd/system/systemd-imdsd@.service.d/50-multi-interface.conf <<EOF
[Service]
Environment=SYSTEMD_IMDS_MULTI_INTERFACE=dummy0,dummy1
EOF
systemctl daemon-reload
systemctl stop systemd-imdsd.socket
systemctl start systemd-imdsd.socket

for i in 1 2 3 4 5 6; do
    assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"
done

rm /run/systemd/system/systemd-imdsd@.service.d/50-multi-interface.conf
systemctl daemon-reload
systemctl stop systemd-imdsd.socket
systemctl start systemd-imdsd.socket
assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"

IMDSD_MULTI="/usr/lib/systemd/systemd-imdsd --vendor=test --data-url=http://192.168.47.11:8088 --well-known-key=hostname:/hostname --multi-interface=yes"
assert_eq "$($IMDSD_MULTI --well-known=hostname)" "piff"

assert_fail /usr/lib/systemd/systemd-imdsd --vendor=test --data-url=http://192.168.47.11:8088 "--multi-interface=bad name with spaces" --well-known=hostname

cat >/run/systemd/system/systemd-imdsd@.service.d/50-multi-interface.conf <<EOF
[Service]
Environment=SYSTEMD_IMDS_MULTI_INTERFACE=yes
EOF
systemctl daemon-reload
systemctl stop systemd-imdsd.socket
systemctl start systemd-imdsd.socket

for i in 1 2 3 4; do
    assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"
done

cat >/run/systemd/system/systemd-imdsd@.service.d/50-multi-interface.conf <<EOF
[Service]
Environment=SYSTEMD_IMDS_MULTI_INTERFACE=no
EOF
systemctl daemon-reload
systemctl stop systemd-imdsd.socket
systemctl start systemd-imdsd.socket
assert_eq "$(/usr/lib/systemd/systemd-imds --well-known=hostname)" "piff"

systemctl stop systemd-imdsd.socket
