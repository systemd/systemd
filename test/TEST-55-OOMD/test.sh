#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="systemd-oomd Memory Pressure Test"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@" 55
