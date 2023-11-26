#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

TEST_NUM=${1?}

(! journalctl -q -o short-monotonic --grep "didn't pass validation" >> /failed)

exit 0
