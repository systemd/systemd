#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

for script in "${0%.sh}".*.sh; do
    echo "Running $script"
    "./$script"
done

touch /testok
rm /failed
