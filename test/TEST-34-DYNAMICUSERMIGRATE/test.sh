#!/usr/bin/env bash
set -e

TEST_DESCRIPTION="test migrating state directory from DynamicUser=1 to DynamicUser=0 and back"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@" 34
