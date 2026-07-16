#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-sysusers - <<EOF
u unlockedtestuser - "An unlocked system user" / /bin/bash
u! lockedtestuser - "A locked system user" / /bin/bash
EOF

if command -v userdbctl >/dev/null; then
    userdbctl -j user unlockedtestuser
    userdbctl -j user lockedtestuser

    assert_eq "$(userdbctl -j user unlockedtestuser | jq .locked)" "null"
    assert_eq "$(userdbctl -j user lockedtestuser | jq .locked)" "true"
fi

at_exit() {
    set +e
    userdel -r foobarbaz
    umount /run/systemd/userdb/
}

# Check that we indeed run under root to make the rest of the test work
[[ "$(id -u)" -eq 0 ]]

trap at_exit EXIT

root="$(mktemp -d)"
cred="$(mktemp -d)"
mkdir -p "$root/etc"
printf 'relative-shell' >"$cred/passwd.shell.creduser"
(! env CREDENTIALS_DIRECTORY="$cred" systemd-sysusers --root="$root" --inline 'u creduser 999 "Cred User" / -')
(! grep -F creduser "$root/etc/passwd" >/dev/null 2>&1)
rm -rf "$root" "$cred"

# Ensure that a non-responsive NSS socket doesn't make sysusers fail
mount -t tmpfs tmpfs /run/systemd/userdb/
touch /run/systemd/userdb/io.systemd.DynamicUser
echo 'u foobarbaz' | SYSTEMD_LOG_LEVEL=debug systemd-sysusers -
grep -q foobarbaz /etc/passwd
