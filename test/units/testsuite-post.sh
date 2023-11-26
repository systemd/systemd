#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

TEST_NUM=${1?}
echo "Running post script for TEST-${TEST_NUM}"

(! journalctl -q -o short-monotonic --grep "didn't pass validation" >> /failed)

exit 0
