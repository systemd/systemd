#!/usr/bin/env bash
set -eux
set -o pipefail

TESTS_GLOB="test-loop-block"
. $(dirname $0)/testsuite-02.sh

exit 0
