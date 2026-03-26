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
    systemctl stop fake-imds systemd-imdsd.socket
    ip link del dummy0
    rm -f /run/credstore/firstboot.hostname /run/credstore/acredtest /run/systemd/system/systemd-imdsd@.service.d/50-env.conf
    rmdir /run/systemd/system/systemd-imdsd@.service.d
}

trap at_exit EXIT

systemd-run -p Type=notify --unit=fake-imds /usr/lib/systemd/tests/integration-tests/TEST-74-AUX-UTILS/TEST-74-AUX-UTILS.units/fake-imds.py
systemctl status fake-imds

# Add a fake network interface so that IMDS gets going
ip link add dummy0 type dummy
ip link set dummy0 up
ip addr add 192.168.47.11/24 dev dummy0

USERDATA='{"systemd.credentials":[{"name":"acredtest","text":"avalue"}]}'

# First try imdsd directly
IMDSD="/usr/lib/systemd/systemd-imdsd --vendor=test --data-url=http://192.168.47.11:8088 --well-known-key=userdata:/userdata --well-known-key=hostname:/hostname"
assert_eq "$($IMDSD --well-known=hostname)" "piff"
assert_eq "$($IMDSD --well-known=userdata)" "$USERDATA"
assert_eq "$($IMDSD /hostname)" "piff"
assert_eq "$($IMDSD /userdata)" "$USERDATA"

# Then, try it as Varlink service
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
