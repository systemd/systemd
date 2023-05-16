#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

assert_eq "$LISTEN_FDS" "2"
assert_eq "$LISTEN_FDNAMES" "open:test-77-file.dat"
read -r -u 3 text
assert_eq "$text" "Open"
read -r -u 4 text
assert_eq "$text" "File"

# Test for socket
systemctl start testsuite-77-server.socket
systemd-run -p OpenFile=/tmp/test.sock:socket:read-only \
            --wait \
            --pipe \
            /usr/lib/systemd/tests/testdata/units/testsuite-77-client.sh

# Tests for D-Bus
diff <(systemctl show -p OpenFile testsuite-77) - <<EOF
OpenFile=/test-77-open.dat:open:read-only
OpenFile=/test-77-file.dat
EOF
echo "New" >/test-77-new-file.dat
systemd-run --wait -p OpenFile=/test-77-new-file.dat:new-file:read-only "$(dirname "$0")"/testsuite-77-run.sh

assert_rc 202 systemd-run --wait -p OpenFile=/test-77-new-file.dat:new-file:read-only -p OpenFile=/test-77-mssing-file.dat:missing-file:read-only "$(dirname "$0")"/testsuite-77-run.sh

assert_rc 0 systemd-run --wait -p OpenFile=/test-77-new-file.dat:new-file:read-only -p OpenFile=/test-77-mssing-file.dat:missing-file:read-only,graceful "$(dirname "$0")"/testsuite-77-run.sh

# End
touch /testok
