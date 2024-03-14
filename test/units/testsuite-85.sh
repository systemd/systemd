#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

for u in pass-fds-to-exec-{no,yes}.socket; do
    systemctl start $u
    systemctl stop $u
done

touch /testok
