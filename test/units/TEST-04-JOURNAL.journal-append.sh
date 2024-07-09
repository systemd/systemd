#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# test-journal-append corrupts the journal file by flipping a bit at a given offset and
# following it by a write to check if we handle appending messages to corrupted journals
# gracefully

TEST_JOURNAL_APPEND=/usr/lib/systemd/tests/unit-tests/manual/test-journal-append

[[ -x "$TEST_JOURNAL_APPEND" ]]

# Corrupt the first ~1024 bytes, this should be pretty quick
"$TEST_JOURNAL_APPEND" --sequential --start-offset=0 --iterations=350 --iteration-step=3

# Skip most of the test when running without acceleration, as it's excruciatingly slow
# (this shouldn't be an issue, as it should run in nspawn as well)
if ! [[ "$(systemd-detect-virt -v)" == "qemu" ]]; then
    # Corrupt the beginning of every 1K block between 1K - 32K
    for ((i = 1024; i <= (32 * 1024); i += 1024)); do
        "$TEST_JOURNAL_APPEND" --sequential --start-offset="$i" --iterations=5 --iteration-step=13
    done

    # Corrupt the beginning of every 16K block between 32K - 128K
    for ((i = (32 * 1024); i <= (256 * 1024); i += (16 * 1024))); do
        "$TEST_JOURNAL_APPEND" --sequential --start-offset="$i" --iterations=5 --iteration-step=13
    done

    # Corrupt the beginning of every 128K block between 128K - 1M
    for ((i = (128 * 1024); i <= (1 * 1024 * 1024); i += (128 * 1024))); do
        "$TEST_JOURNAL_APPEND" --sequential --start-offset="$i" --iterations=5 --iteration-step=13
    done

    # And finally the beginning of every 1M block between 1M and 8M
    for ((i = (1 * 1024 * 1024); i < (8 * 1024 * 1024); i += (1 * 1024 * 1024))); do
        "$TEST_JOURNAL_APPEND" --sequential --start-offset="$i" --iterations=5 --iteration-step=13
    done

    if [[ "$(nproc)" -ge 2 ]]; then
        # Try to corrupt random bytes throughout the journal
        "$TEST_JOURNAL_APPEND" --iterations=25
    fi
else
    "$TEST_JOURNAL_APPEND" --iterations=10
fi
