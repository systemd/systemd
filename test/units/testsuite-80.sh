#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

export SYSTEMD_LOG_LEVEL=debug

systemctl start testsuite-80-succeeds-on-restart.target || true
assert_rc 0 systemctl --quiet is-active testsuite-80-succeeds-on-restart.target

systemctl start testsuite-80-fails-on-restart.target || true
assert_rc 3 systemctl --quiet is-active testsuite-80-fails-on-restart.target

# End
touch /testok
