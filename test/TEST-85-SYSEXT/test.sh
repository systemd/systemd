#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -e

TEST_DESCRIPTION="test systemd-sysext"
IMAGE_NAME="sysext"

# TODO: I have no idea about those.
TEST_NO_NSPAWN=1
TEST_INSTALL_VERITY_MINIMAL=1

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

do_test "$@"
