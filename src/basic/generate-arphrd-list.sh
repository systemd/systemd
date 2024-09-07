#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

${1:?} -dM -include "${2:?}" -include "${3:?}" - </dev/null | \
       awk '/^#define[ \t]+ARPHRD_[^ \t]+[ \t]+[^ \t]/ { print $2; }' | \
       sed -e 's/ARPHRD_//'
