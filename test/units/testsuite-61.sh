#!/usr/bin/env bash
set -eux
set -o pipefail

TESTS_GLOB="test-loop-block"
# shellcheck source=test/units/testsuite-02.sh
. "$(dirname "$0")/testsuite-02.sh"

exit 0
