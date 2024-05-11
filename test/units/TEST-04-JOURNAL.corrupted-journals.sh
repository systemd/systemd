#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

JOURNAL_DIR="$(mktemp -d)"
REMOTE_OUT="$(mktemp -d)"
# tar on C8S doesn't support the --zstd option
unzstd --stdout "/usr/lib/systemd/tests/testdata/test-journals/afl-corrupted-journals.tar.zst" | tar -xC "$JOURNAL_DIR/"
while read -r file; do
    filename="${file##*/}"
    unzstd "$file" -o "$JOURNAL_DIR/${filename%*.zst}"
done < <(find /usr/lib/systemd/tests/testdata/test-journals/corrupted/ -name "*.zst")
# First, try each of them sequentially. Skip this part when running with plain
# QEMU, as it is excruciatingly slow
# Note: we care only about exit code 124 (timeout) and special bash exit codes
# >124 (like signals)
if [[ "$(systemd-detect-virt -v)" != "qemu" ]]; then
    while read -r file; do
        timeout 10 journalctl --file="$file" --boot >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --verify >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --output=export >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --fields >/dev/null || [[ $? -lt 124 ]]
        timeout 10 journalctl --file="$file" --list-boots >/dev/null || [[ $? -lt 124 ]]
        if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
            timeout 10 /usr/lib/systemd/systemd-journal-remote \
                            --getter="journalctl --file=$file --output=export" \
                            --split-mode=none \
                            --output="$REMOTE_OUT/system.journal" || [[ $? -lt 124 ]]
            timeout 10 journalctl --directory="$REMOTE_OUT" >/dev/null || [[ $? -lt 124 ]]
            rm -f "$REMOTE_OUT"/*
        fi
    done < <(find "$JOURNAL_DIR" -type f)
fi
# And now all at once
timeout 30 journalctl --directory="$JOURNAL_DIR" --boot >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --verify >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --output=export >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --fields >/dev/null || [[ $? -lt 124 ]]
timeout 30 journalctl --directory="$JOURNAL_DIR" --list-boots >/dev/null || [[ $? -lt 124 ]]
if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
    timeout 30 /usr/lib/systemd/systemd-journal-remote \
                    --getter="journalctl --directory=$JOURNAL_DIR --output=export" \
                    --split-mode=none \
                    --output="$REMOTE_OUT/system.journal" || [[ $? -lt 124 ]]
    timeout 30 journalctl --directory="$REMOTE_OUT" >/dev/null || [[ $? -lt 124 ]]
    rm -f "$REMOTE_OUT"/*
fi
