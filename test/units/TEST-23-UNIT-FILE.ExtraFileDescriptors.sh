#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e

    rm -rf /tmp/test-extra-fd/
}

trap at_exit EXIT

mkdir /tmp/test-extra-fd
echo "Hello" > /tmp/test-extra-fd/1.txt
echo "Extra" > /tmp/test-extra-fd/2.txt

systemd-analyze log-level debug

# Open files and assign FD to variables
exec {TEST_FD1}</tmp/test-extra-fd/1.txt
exec {TEST_FD2}</tmp/test-extra-fd/2.txt

TEST_UNIT="test-23-extra-fd.service"

busctl call \
    org.freedesktop.systemd1 /org/freedesktop/systemd1 \
    org.freedesktop.systemd1.Manager StartTransientUnit \
    "ssa(sv)a(sa(sv))" "$TEST_UNIT" replace 4 \
      ExecStart "a(sasb)" 1 \
        /usr/lib/systemd/tests/testdata/units/TEST-23-UNIT-FILE-ExtraFileDescriptors-child.sh \
        5 /usr/lib/systemd/tests/testdata/units/TEST-23-UNIT-FILE-ExtraFileDescriptors-child.sh 2 "test:other" "Hello" "Extra" \
        true \
      RemainAfterExit "b" true \
      Type "s" oneshot \
      ExtraFileDescriptors "a(hs)" 2 \
        "$TEST_FD1" test \
        "$TEST_FD2" other \
    0

cmp -b <(systemctl show -p ExtraFileDescriptorNames "$TEST_UNIT") <<EOF
ExtraFileDescriptorNames=test other
EOF

# shellcheck disable=SC2016
timeout 10s bash -xec 'while [[ "$(systemctl show -P SubState test-23-extra-fd.service)" != "exited" ]]; do sleep .5; done'

assert_eq "$(systemctl show -P Result "$TEST_UNIT")" "success"
assert_eq "$(systemctl show -P ExecMainStatus "$TEST_UNIT")" "0"

# Verify extra file descriptors stay accessible even after service manager re-executes
systemctl daemon-reexec

systemctl restart "$TEST_UNIT"

assert_eq "$(systemctl show -P SubState "$TEST_UNIT")" "exited"
assert_eq "$(systemctl show -P Result "$TEST_UNIT")" "success"
assert_eq "$(systemctl show -P ExecMainStatus "$TEST_UNIT")" "0"

systemctl stop "$TEST_UNIT"

systemctl log-level info
