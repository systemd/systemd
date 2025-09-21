#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run --wait \
        /usr/lib/systemd/tests/unit-tests/manual/test-thp-no-disable

systemd-run --wait \
        -p MemoryTHP=disable \
        /usr/lib/systemd/tests/unit-tests/manual/test-thp-disable-completely
