#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

(! journalctl -q -o short-monotonic --grep "didn't pass validation" >>/failed)

# Here, the redundant '[.]' at the end is for making not the logged self command hit the grep.
(! journalctl -q -o short-monotonic --grep 'Attempted to close sd-bus after fork whose connection is opened before the fork, this should not happen[.]' >>/failed)

systemctl poweroff --no-block
exit 0
