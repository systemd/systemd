#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test migrating state directory from DynamicUser=1 to DynamicUser=0 and back"
# Certain subtests run with DynamicUser=true which makes writing the gcov
# artifacts impossible. As $GCOV_PREFIX and friends seem to be ineffective
# in this situation, let's simply ignore all gcov complaints for the whole
# test to make it happy.
IGNORE_MISSING_COVERAGE=yes

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
