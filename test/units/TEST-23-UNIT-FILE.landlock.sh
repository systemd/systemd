#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

cleanup() {
    set +e
    rm -rf /tmp/test-landlock
    systemctl stop TEST-23-UNIT-FILE-landlock-denied.service || :
    systemctl stop TEST-23-UNIT-FILE-landlock-allowed.service || :
}

trap cleanup EXIT

mkdir -p /tmp/test-landlock

# Test #1: Forbidden /tmp/test-landlock

systemctl start TEST-23-UNIT-FILE-landlock-denied.service && exit 1

# shellcheck disable=SC2016
timeout 10s bash -xec 'while [[ "$(systemctl show -P SubState TEST-23-UNIT-FILE-landlock-denied.service)" != "failed" ]]; do sleep .5; done'

assert_eq "$(systemctl show -P Result TEST-23-UNIT-FILE-landlock-denied.service)" "exit-code"
assert_eq "$(systemctl show -P ExecMainStatus TEST-23-UNIT-FILE-landlock-denied.service)" "1"

[[ ! -f /tmp/test-landlock/date.txt ]]

# No need to remove /tmp/test-landlock/date.txt

# Test #2: Allowed /tmp/test-landlock

systemctl start TEST-23-UNIT-FILE-landlock-allowed.service

# shellcheck disable=SC2016
timeout 10s bash -xec 'while [[ "$(systemctl show -P SubState TEST-23-UNIT-FILE-landlock-allowed.service)" != "dead" ]]; do sleep .5; done'

assert_eq "$(systemctl show -P Result TEST-23-UNIT-FILE-landlock-allowed.service)" "success"
assert_eq "$(systemctl show -P ExecMainStatus TEST-23-UNIT-FILE-landlock-allowed.service)" "0"

[[ -f /tmp/test-landlock/date.txt ]]
