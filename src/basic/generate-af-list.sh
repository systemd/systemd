#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

${1:?} -E -dM -include sys/socket.h -include "${2:?}" -include "${3:?}" - </dev/null | \
       grep -Ev 'AF_UNSPEC|AF_MAX' | \
       awk '/^#define[ \t]+AF_[^ \t]+[ \t]+[AP]F_[^ \t]/ { print $2; }'
