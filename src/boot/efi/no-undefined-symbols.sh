#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

if nm -D -u "${1:?}" | grep ' U '; then
    echo "Undefined symbols detected!"
    exit 1
fi
