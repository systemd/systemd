#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

HOSTNAME="$(hostnamectl hostname)"

testcase_yes() {
    (! systemd-run --wait -p ProtectHostname=yes hostnamectl hostname foo)

    systemd-run --wait -p ProtectHostname=yes -p PrivateMounts=yes \
        findmnt --mountpoint /proc/sys/kernel/hostname
}

testcase_private() {
    systemd-run --wait -p ProtectHostnameEx=private \
        -P bash -xec '
            hostnamectl hostname foo
            test "$(hostnamectl hostname)" = "foo"
        '

    # Verify host hostname is unchanged.
    test "$(hostnamectl hostname)" = "$(HOSTNAME)"

    # Verify /proc/sys/kernel/hostname is not bind mounted from host read-only.
    (! systemd-run --wait -p ProtectHostnameEx=private -p PrivateMounts=yes \
        findmnt --mountpoint /proc/sys/kernel/hostname)
}

run_testcases
