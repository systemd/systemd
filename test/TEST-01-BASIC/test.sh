#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="Basic systemd setup"
IMAGE_NAME="basic"
RUN_IN_UNPRIVILEGED_CONTAINER=${RUN_IN_UNPRIVILEGED_CONTAINER:-yes}
TEST_REQUIRE_INSTALL_TESTS=0
TEST_SUPPORTING_SERVICES_SHOULD_BE_MASKED=0

# Check if we can correctly deserialize if the kernel cmdline contains "weird" stuff
# like an invalid argument, "end of arguments" separator, or a sysvinit argument (-z)
# See: https://github.com/systemd/systemd/issues/28184
KERNEL_APPEND="foo -- -z bar --- baz $KERNEL_APPEND"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
