#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

. /etc/os-release
# FIXME: This test fails on opensuse with the following error and others:
# Apr 25 10:24:04 H (cat)[910]: device-mapper: create ioctl on ... failed: Device or resource busy
if [[ "$ID" =~ "opensuse" ]]; then
    echo "Skipping due to known unexpected behaviour in OpenSUSE kernels" >>/skipped
    exit 77
fi

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

run_subtests

touch /testok
