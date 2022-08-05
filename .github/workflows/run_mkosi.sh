#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2064

set -eu
set -o pipefail

EC=0
TEMPFILE="$(mktemp)"
TEMP_EXTRA_TREE="$(mktemp --directory)"
trap "rm -rf '$TEMPFILE' '$TEMP_EXTRA_TREE'" EXIT

# We need isc-dhcp-server to be installed for the networkd unit tests, but we don't want to
# run it by default. mktemp creates the directory as 700, so change it, otherwise it will
# affect the image's root folder permissions.
chmod 755 "$TEMP_EXTRA_TREE"
mkdir -p "$TEMP_EXTRA_TREE/etc/systemd/system/"
ln -s /dev/null "$TEMP_EXTRA_TREE/etc/systemd/system/isc-dhcp-server.service"
ln -s /dev/null "$TEMP_EXTRA_TREE/etc/systemd/system/isc-dhcp-server6.service"

for ((i = 0; i < 5; i++)); do
    EC=0
    (sudo timeout -k 30 10m python3 -m mkosi --extra-tree="$TEMP_EXTRA_TREE" "$@") |& tee "$TEMPFILE" || EC=$?
    if [[ $EC -eq 0 ]]; then
        # The command passed — let's return immediately
        break
    fi

    if ! grep -E "Failed to dissect image .+: Connection timed out" "$TEMPFILE"; then
        # The command failed for other reason than the dissect-related timeout -
        # let's exit with the same EC
        exit $EC
    fi

    # The command failed due to the dissect-related timeout — let's try again
    sleep 1
done

exit $EC
