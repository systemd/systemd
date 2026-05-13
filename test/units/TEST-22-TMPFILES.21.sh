#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2235
set -eux

# Test L?

rm -rf /tmp/tmpfiles

root="/tmp/tmpfiles"
mkdir "$root"
touch "$root/abc"

SYSTEMD_LOG_LEVEL=debug systemd-tmpfiles --create - --root=$root <<EOF
L? /i-dont-exist - - - - /def
L? /i-do-exist - - - - /abc
EOF

(! test -L "$root/i-dont-exist")
test -L "$root/i-do-exist"
