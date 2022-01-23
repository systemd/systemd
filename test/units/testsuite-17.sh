#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

: >/failed

if [[ -x /usr/lib/systemd/tests/test-sd-device-monitor ]]; then
    SYSTEMD_LOG_LEVEL=debug /usr/lib/systemd/tests/test-sd-device-monitor && ret=0 || ret=$?
    if [[ $ret -ne 0 && $ret != 77 ]]; then
        return $ret
    fi
fi

udevadm settle

for t in "${0%.sh}".*.sh; do
    echo "Running $t"; ./"$t"
done

echo "Test passed, but simulating fail to get journals"
