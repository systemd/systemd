#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Test support for units with long (longer than FILENAME_MAX) names"

# shellcheck source=test/test-functions
. "$TEST_BASE_DIR/test-functions"

do_test "$@"
