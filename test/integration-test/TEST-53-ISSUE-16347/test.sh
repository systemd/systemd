#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="test timer units when initial clock is ahead"
TEST_NO_NSPAWN=1

QEMU_OPTIONS+=" -rtc base=$(date -u +%Y-%m-%dT%H:%M:%S -d '+3 days')"

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
