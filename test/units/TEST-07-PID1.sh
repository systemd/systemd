#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

# Issue: https://github.com/systemd/systemd/issues/2730
# See TEST-07-PID1/test.sh for the first "half" of the test
mountpoint /issue2730

run_subtests

touch /testok
systemctl --no-block exit 123
