#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

# Issue: https://github.com/systemd/systemd/issues/2730
# See TEST-07-PID1/test.sh for the first "half" of the test
mountpoint /issue2730

for script in "${0%.sh}".*.sh; do
    echo "Running $script"
    "./$script"
done

touch /testok
rm /failed
