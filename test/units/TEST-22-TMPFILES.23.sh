#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# Regression test for https://github.com/systemd/systemd/issues/44435
#
# "x" entries without an age must not make "systemd-tmpfiles --clean" fail when the specified directory
# cannot be opened (e.g. EACCES on a FUSE mount, or a directory with mode 0000).
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e

    rm -rf "${TESTDIR:-}"
}

trap at_exit EXIT

TESTDIR="$(mktemp -d /tmp/test-tmpfiles-ignore-eacces.XXXXXXXX)"

# aaa: not excluded (must be cleaned up), xxx: excluded by "x"
mkdir -p "$TESTDIR/root/aaa/aaa" "$TESTDIR/root/xxx/xxx"
touch "$TESTDIR/root/aaa/aaa/aaa" "$TESTDIR/root/xxx/xxx/xxx"

cat >"$TESTDIR/test.conf" <<EOF
d $TESTDIR/root         - - - 1us -
x $TESTDIR/root/xxx     - - - -   -
EOF

# root bypasses the DAC checks (CAP_DAC_OVERRIDE), so the EACCES condition cannot be reproduced as root.
# Hence, make the tree owned by testuser, and run systemd-tmpfiles as testuser.
chown -R testuser:testuser "$TESTDIR/root" "$TESTDIR/test.conf"
chmod 0755 "$TESTDIR"
chmod 0644 "$TESTDIR/test.conf"
chmod 0000 "$TESTDIR/root/xxx"

# Make sure that everything is older than the age (1us) of the "d" entry.
sleep .1

SYSTEMD_LOG_LEVEL=debug runas testuser systemd-tmpfiles --clean "$TESTDIR/test.conf"
test -e "$TESTDIR/root/xxx/xxx/xxx"
test ! -e "$TESTDIR/root/aaa"
