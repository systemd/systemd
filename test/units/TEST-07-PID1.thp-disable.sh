#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run --wait \
        /usr/lib/systemd/tests/unit-tests/manual/test-thp no-disable

systemd-run --wait \
        -p MemoryTHP=disable \
        /usr/lib/systemd/tests/unit-tests/manual/test-thp disable

# The following test will always return 77 if at compile time the kernel version
# is less than 6.18. If it happens don't let the whole test fail
set +e

systemd-run --wait \
        -p MemoryTHP=madvise \
        /usr/lib/systemd/tests/unit-tests/manual/test-thp madvise

if [ $? -eq 77 ]; then
        exit 0
fi

set -e
