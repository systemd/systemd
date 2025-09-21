#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail


# Check that our helper is able to get a BPF token
systemd-run --wait \
        -p MemoryTHPMadvise=yes \
        /usr/lib/systemd/tests/unit-tests/manual/test-prctl-thp-madvise
