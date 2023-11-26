#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

(! journalctl -q -o short-monotonic --grep "didn't pass validation" >>/failed)

systemctl poweroff --no-block
exit 0
