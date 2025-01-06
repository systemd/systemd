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

    rm -f /tmp/output-i /tmp/output-I

    rm -rf /run/udev/rules.d/
    udevadm control --reload

    rm -f /run/systemd/system/test@.service
    systemctl daemon-reload

    ip link del "$IFNAME"
}

trap at_exit EXIT

udevadm settle --timeout 30

mkdir -p /run/systemd/system/
cat >/run/systemd/system/test@.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -xec 'echo "i=%i" >/tmp/output-i; echo "I=/%I" >/tmp/output-I'
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
SHELL_ESCAPED=$(printf '%q' "${ESCAPED}")
assert_eq "$(systemd-escape -u -p "${ESCAPED}")" "${SYSPATH}"

udevadm wait --timeout 30 --settle "/sys/class/net/${IFNAME}"
assert_eq "$(udevadm info --query=property --property SYSTEMD_WANTS --value "/sys/class/net/${IFNAME}")" "test@${ESCAPED}.service"
# The value shown by systemctl is doubly escaped and quoted.
assert_eq "$(systemctl show -p Wants --value "${ESCAPED}.device")" "\"test@${SHELL_ESCAPED}.service\""

timeout 30 bash -c 'until [[ -s /tmp/output-i ]] && [[ -s /tmp/output-I ]]; do sleep .5; done'
assert_eq "$(cat /tmp/output-i)" "i=${ESCAPED}"
assert_eq "$(cat /tmp/output-I)" "I=${SYSPATH}"

exit 0
