#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

udevadm settle

for t in "${0%.sh}".*.sh; do
    echo "Running $t"; ./"$t"
done

touch /testok
rm /failed
