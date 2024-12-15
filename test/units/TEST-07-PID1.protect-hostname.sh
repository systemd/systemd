#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

LEGACY_HOSTNAME="$(hostname)"
HOSTNAME_FROM_SYSTEMD="$(hostnamectl hostname)"

testcase_yes() {
    # hostnamectl calls SetHostname method via dbus socket which executes in homenamed
    # in the init namespace. So hostnamectl is not affected by ProtectHostname=yes or
    # private since sethostname() system call is executed in the init namespace.
    #
    # hostnamed does authentication based on UID via polkit so this guarantees admins
    # can only set hostname.
    (! systemd-run --wait -p ProtectHostname=yes hostname foo)

    systemd-run --wait -p ProtectHostname=yes -p PrivateMounts=yes \
        findmnt --mountpoint /proc/sys/kernel/hostname
}

testcase_private() {
    systemd-run --wait -p ProtectHostnameEx=private -p PrivateHostname=hoge \
        -P bash -xec '
            test "$(hostname)" = "hoge"
            hostname foo
            test "$(hostname)" = "foo"
        '

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    # PrivateHostname= implies ProtectHostname=
    systemd-run --wait -p PrivateHostname=hoge \
        -P bash -xec '
            test "$(hostname)" = "hoge"
            hostname foo
            test "$(hostname)" = "foo"
        '

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    # PrivateHostname= combined with ProtectHostname=yes/no is refused
    (! systemd-run --wait -p ProtectHostname=yes -p PrivateHostname=hoge true)
    (! systemd-run --wait -p ProtectHostname=no  -p PrivateHostname=hoge true)

    # Verify /proc/sys/kernel/hostname is not bind mounted from host read-only.
    (! systemd-run --wait -p ProtectHostnameEx=private -p PrivateMounts=yes \
        findmnt --mountpoint /proc/sys/kernel/hostname)
}

run_testcases
