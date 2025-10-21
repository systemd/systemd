#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# For issue #38765
journalctl --sync
if journalctl -q -o short-monotonic --grep "Looking at job .*/.* conflicted_by=(yes|no)" >/failed; then
    echo "Found unexpected unmergeable jobs"
    cat /failed
    exit 1
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

run_subtests

touch /testok
