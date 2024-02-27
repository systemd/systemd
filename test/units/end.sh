#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

(! journalctl -q -o short-monotonic --grep "didn't pass validation" >>/failed)

# Here, the redundant '[ ]' in the pattern is required in order not to match the logged command itself.
(! journalctl -q -o short-monotonic --grep 'Warning: cannot close sd-bus connection[ ].*after fork' >>/failed)

systemctl poweroff --no-block
exit 0
