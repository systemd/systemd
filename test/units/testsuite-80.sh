#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

: >/failed

systemctl --no-block start notify.service
sleep 3

assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"
sleep 10

systemctl --quiet is-active notify.service
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "main"
assert_eq "$(systemctl show notify.service -p StatusText --value)" "OK"

systemctl stop notify.service
assert_eq "$(systemctl show notify.service -p NotifyAccess --value)" "all"

touch /testok
rm /failed
