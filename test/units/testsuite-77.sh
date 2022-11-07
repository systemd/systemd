#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug

assert_eq "$LISTEN_FDS" "2"
assert_eq "$LISTEN_FDNAMES" "open:file"
read -r -u 3 text
assert_eq "$text" "Open"
read -r -u 4 text
assert_eq "$text" "File"

# Test for socket
systemctl start testsuite-77-netcat.service
systemctl start testsuite-77-socket.service

# Tests for D-Bus
diff <(systemctl show -p OpenFile testsuite-77) - <<EOF
OpenFile=/test-77-open.dat:open:ro
OpenFile=/test-77-file.dat:file:ro
EOF
echo "New" > /test-77-new-file.dat
systemd-run --wait -p OpenFile=/test-77-new-file.dat:new-file:ro "$(dirname "$0")"/testsuite-77-run.sh

assert_rc 1 systemd-run --wait -p OpenFile=/test-77-new-file.dat:new-file:ro -p OpenFile=/test-77-mssing-file.dat:missing-file:ro "$(dirname "$0")"/testsuite-77-run.sh

assert_rc 0 systemd-run --wait -p OpenFile=/test-77-new-file.dat:new-file:ro -p OpenFile=/test-77-mssing-file.dat:missing-file:ro,graceful "$(dirname "$0")"/testsuite-77-run.sh

# End
touch /testok
