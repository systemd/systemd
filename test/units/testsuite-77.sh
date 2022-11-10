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

systemctl start testsuite-77-netcat.service

systemctl start testsuite-77-openfile.service

touch /testok
