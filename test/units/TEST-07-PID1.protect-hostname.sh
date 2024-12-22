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

    # ProtectHostname=yes can optionally take a hostname.
    systemd-run --wait -p ProtectHostnameEx=yes:hoge \
        -P bash -xec '
            test "$(hostname)" = "hoge"
            (! hostname foo)
            test "$(hostname)" = "hoge"
        '

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    # ProtectHostname= supports specifiers.
    mkdir -p /run/systemd/system/
    cat >/run/systemd/system/test-protect-hostname-yes@.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -xec 'test "\$\$(hostname)" = "%i"; (! hostname foo); test "\$\$(hostname)" = "%i"'
ProtectHostname=yes:%i
EOF
    systemctl daemon-reload
    systemctl start --wait test-protect-hostname-yes@hoge.example.com.service

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    systemd-run --wait -p ProtectHostname=yes -p PrivateMounts=yes \
        findmnt --mountpoint /proc/sys/kernel/hostname
}

testcase_private() {
    systemd-run --wait -p ProtectHostnameEx=private \
        -P bash -xec '
            hostname foo
            test "$(hostname)" = "foo"
        '

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    # ProtectHostname=private can optionally take a hostname.
    systemd-run --wait -p ProtectHostnameEx=private:hoge \
        -P bash -xec '
            test "$(hostname)" = "hoge"
            hostname foo
            test "$(hostname)" = "foo"
        '

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    # ProtectHostname= supports specifiers.
    mkdir -p /run/systemd/system/
    cat >/run/systemd/system/test-protect-hostname-private@.service <<EOF
[Service]
Type=oneshot
ExecStart=bash -xec 'test "\$\$(hostname)" = "%i"; hostname foo; test "\$\$(hostname)" = "foo"'
ProtectHostname=private:%i
EOF
    systemctl daemon-reload
    systemctl start --wait test-protect-hostname-private@hoge.example.com.service

    # Verify host hostname is unchanged.
    test "$(hostname)" = "$LEGACY_HOSTNAME"
    test "$(hostnamectl hostname)" = "$HOSTNAME_FROM_SYSTEMD"

    # Verify /proc/sys/kernel/hostname is not bind mounted from host read-only.
    (! systemd-run --wait -p ProtectHostnameEx=private -p PrivateMounts=yes \
        findmnt --mountpoint /proc/sys/kernel/hostname)
}

testcase_invalid() {
    # ProtectHostname=no cannot take hostname.
    (! systemd-run --wait -p ProtectHostnameEx=no:hoge true)

    # Invalid hostname.
    (! systemd-run --wait -p ProtectHostnameEx=yes: true)
    (! systemd-run --wait -p ProtectHostnameEx=yes:.foo true)
    (! systemd-run --wait -p ProtectHostnameEx=yes:foo.-example.com true)
    (! systemd-run --wait -p ProtectHostnameEx=yes:foo..example.com true)
    (! systemd-run --wait -p ProtectHostnameEx=private: true)
    (! systemd-run --wait -p ProtectHostnameEx=private:.foo true)
    (! systemd-run --wait -p ProtectHostnameEx=private:foo.-example.com true)
    (! systemd-run --wait -p ProtectHostnameEx=private:foo..example.com true)
}

run_testcases
