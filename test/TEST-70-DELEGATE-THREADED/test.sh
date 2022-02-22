#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test threaded cgroup in unit with Delegate=yes"

TEST_PREFER_NSPAWN=1
UNIFIED_CGROUP_HIERARCHY=yes

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
