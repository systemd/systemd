#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

get_first_boot_id() {
    journalctl -b "${1:?}" -o json -n +1 | jq -r '._BOOT_ID'
}

get_last_boot_id() {
    journalctl -b "${1:?}" -o json -n 1 | jq -r '._BOOT_ID'
}

get_first_timestamp() {
    journalctl -b "${1:?}" -o json -n +1 | jq -r '.__REALTIME_TIMESTAMP'
}

get_last_timestamp() {
    journalctl -b "${1:?}" -o json -n 1 | jq -r '.__REALTIME_TIMESTAMP'
}

# Issue: #29275, second part
# Now let's check if the boot entries are in the correct/expected order
index=0
SYSTEMD_LOG_LEVEL=debug journalctl --list-boots
journalctl --list-boots -o json | jq -r '.[] | [.index, .boot_id, .first_entry, .last_entry] | @tsv' |
    while read -r offset boot_id first_ts last_ts; do
        : "Boot #$((++index)) ($offset) with ID $boot_id"

        # Try the "regular" (non-json) variants first, as they provide a helpful
        # error message if something is not right
        SYSTEMD_LOG_LEVEL=debug journalctl -q -n 0 -b "$index"
        SYSTEMD_LOG_LEVEL=debug journalctl -q -n 0 -b "$offset"
        SYSTEMD_LOG_LEVEL=debug journalctl -q -n 0 -b "$boot_id"

        # Check the boot ID of the first entry
        entry_boot_id="$(get_first_boot_id "$index")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_first_boot_id "$offset")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_first_boot_id "$boot_id")"
        assert_eq "$entry_boot_id" "$boot_id"

        # Check the timestamp of the first entry
        entry_ts="$(get_first_timestamp "$index")"
        assert_eq "$entry_ts" "$first_ts"
        entry_ts="$(get_first_timestamp "$offset")"
        assert_eq "$entry_ts" "$first_ts"
        entry_ts="$(get_first_timestamp "$boot_id")"
        assert_eq "$entry_ts" "$first_ts"

        # Check the boot ID of the last entry
        entry_boot_id="$(get_last_boot_id "$index")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_last_boot_id "$offset")"
        assert_eq "$entry_boot_id" "$boot_id"
        entry_boot_id="$(get_last_boot_id "$boot_id")"
        assert_eq "$entry_boot_id" "$boot_id"

        # Check the timestamp of the last entry
        if [[ "$offset" != "0" ]]; then
            entry_ts="$(get_last_timestamp "$index")"
            assert_eq "$entry_ts" "$last_ts"
            entry_ts="$(get_last_timestamp "$offset")"
            assert_eq "$entry_ts" "$last_ts"
            entry_ts="$(get_last_timestamp "$boot_id")"
            assert_eq "$entry_ts" "$last_ts"
        fi
    done
