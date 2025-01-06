#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2317
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# This is a test case for #16735.

IFNAME=test-netif-foo

at_exit() {
    set +e

    rm -rf /run/systemd/system/ /run/udev/rules.d/
    udevadm control --reload
    systemctl daemon-reload
    ip link del "$IFNAME"
}

trap at_exit EXIT

udevadm settle

mkdir -p /run/systemd/system/
cat >/run/systemd/system/test@.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -xec 'echo i=%i >/tmp/output-i; echo I=%i >/tmp/output-I'
RemainAfterExit=yes
EOF

systemctl daemon-reload

mkdir -p /run/udev/rules.d/
cat >/run/udev/rules.d/99-testsuite.rules <<EOF
SUBSYSTEM=="net", KERNEL=="${IFNAME}", ACTION=="add", OPTIONS="log_level=debug", \
  PROGRAM="/usr/bin/systemd-escape -p %S%p", ENV{SYSTEMD_WANTS}+="test@%c.service"
EOF

udevadm control --reload

ip link add "$IFNAME" type dummy
SYSPATH="/sys$(udevadm info --query=property --property DEVPATH --value "/sys/class/net/${IFNAME}")"
ESCAPED=$(systemd-escape -p "${SYSPATH}")
assert_eq "$(systemd-escape -u -p "${ESCAPED}")" "${SYSPATH}"

systemctl start "${ESCAPED}.device"
# The value shown by systemctl is doubly escaped and quoted.
assert_eq "$(systemctl show -p Wants --value "${ESCAPED}.device")" "$(printf '"%q"' test@${ESCAPED}.service)"

timeout 30 bash -c "until systemctl -q is-active test@${ESCAPED}.service; do sleep .5; done"
assert_eq "$(cat /tmp/output-i)" "i=${ESCAPED}"
assert_eq "$(cat /tmp/output-I)" "I=${SYSPATH}"

exit 0
