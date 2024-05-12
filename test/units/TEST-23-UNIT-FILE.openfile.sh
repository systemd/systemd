#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

at_exit() {
    set +e

    rm -rf /tmp/test-open-file/
}

trap at_exit EXIT

systemctl log-level debug

# Existing files

mkdir /tmp/test-open-file
echo "Open" >'/tmp/test-open-file/open.txt'
echo "File" >'/tmp/test-open-file/file:colon.txt'

systemd-run -p DynamicUser=yes -p EnvironmentFile=-/usr/lib/systemd/systemd-asan-env \
            -p OpenFile='/tmp/test-open-file/open.txt::read-only' \
            -p OpenFile='/tmp/test-open-file/file\x3Acolon.txt:colon' \
            -p RemainAfterExit=yes \
            --unit=test-23-openfile-existing.service \
            --service-type=oneshot \
            /usr/lib/systemd/tests/testdata/units/TEST-23-UNIT-FILE-openfile-child.sh 2 "open.txt:colon" "Open" "File"

cmp <(systemctl show -p OpenFile test-23-openfile-existing.service) <<EOF
OpenFile=/tmp/test-open-file/open.txt::read-only
OpenFile=/tmp/test-open-file/file\\x3acolon.txt:colon
EOF

systemctl stop test-23-openfile-existing.service

# Sockets

systemctl start TEST-23-UNIT-FILE-openfile-server.socket

systemd-run -p OpenFile=/tmp/test.sock:socket:read-only \
            --wait \
            /usr/lib/systemd/tests/testdata/units/TEST-23-UNIT-FILE-openfile-child.sh 1 "socket" "Socket"

systemctl stop TEST-23-UNIT-FILE-openfile-server.socket

# Ignore when missing

assert_rc 202 systemd-run -p OpenFile=/run/missing/foo:missing-file:read-only --wait true
assert_rc 0 systemd-run -p OpenFile=/run/missing/foo:missing-file:read-only,graceful --wait true

systemctl log-level info
