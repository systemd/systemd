#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

TESTS_GLOB="test-loop-block"
# shellcheck source=test/units/testsuite-02.sh
. "$(dirname "$0")/testsuite-02.sh"

exit 0
