#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Test for C-style escapes in file names and contents
set -eux
set -o pipefail

data="\x20foo\nbar"
dst="/tmp/x/\x20a\nb"

systemd-tmpfiles --create - <<EOF
f     "$dst" 0644 0 0 - $data
EOF

diff "$(printf "/tmp/x/\x20a\nb")" <(printf "\x20foo\nbar")
