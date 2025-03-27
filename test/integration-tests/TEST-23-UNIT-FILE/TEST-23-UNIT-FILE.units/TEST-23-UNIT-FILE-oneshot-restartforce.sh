#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [[ -f "$1" ]]; then
    exit 0
fi

touch "$1"
exit 2
