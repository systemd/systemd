#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

: >/failed

systemctl --no-block start notify.service
sleep 2

assert_eq "$(systemctl show notify.service -p StatusText --value)" "Test starts, waiting for 5 seconds"
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"
sleep 5

assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "main"
assert_eq "$(systemctl show notify.service -p StatusText --value)" "Sending READY=1 in an unpriviledged process"
assert_rc 3 systemctl --quiet is-active notify.service
sleep 10

systemctl --quiet is-active notify.service
assert_eq "$(systemctl show notify.service -p StatusText --value)" "OK"
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "none"

systemctl stop notify.service
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"

touch /testok
rm /failed
