#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

VARLINK_SOCKET="/run/systemd/io.systemd.JournalAccess"

# ensure the varlink basics work
varlinkctl list-interfaces "$VARLINK_SOCKET" | grep io.systemd.JournalAccess
varlinkctl introspect "$VARLINK_SOCKET" | grep "method GetEntries("

# lets start with a basic log entry
TAG="$(systemd-id128 new)"
echo "varlink-test-message" | systemd-cat -t "$TAG"
systemd-cat -t "$TAG" -p warning echo "varlink-test-warning"
journalctl --sync

# most basic call works
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{}' | jq --seq .
# validate the JSON has some basic properties (similar to journalctls json output)
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{}' | jq --seq '.entry | {MESSAGE, PRIORITY, _UID}'

# check that default limit works (100), we don't know how many entries we have so we just check
# bounds
ENTRIES=$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{}' | wc -l)
test "$ENTRIES" -gt 0
test "$ENTRIES" -le 100

# check explicit limit
ENTRIES=$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"limit": 3}' | wc -l)
test "$ENTRIES" -le 3

# check unit filter: use transient units to get deterministic results
UNIT_NAME_1="test-journalctl-varlink-1-$RANDOM.service"
systemd-run --unit="$UNIT_NAME_1" --wait bash -c 'echo hello-from-varlink-test-1'
UNIT_NAME_2="test-journalctl-varlink-2-$RANDOM.service"
systemd-run --unit="$UNIT_NAME_2" --wait bash -c 'echo hello-from-varlink-test-2'
journalctl --sync

# single unit filter
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries "{\"units\": [\"$UNIT_NAME_1\"]}" | grep -q "hello-from-varlink-test-1"
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries "{\"units\": [\"$UNIT_NAME_1\"]}" | grep "hello-from-varlink-test-2")
# multi unit filter
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries "{\"units\": [\"$UNIT_NAME_1\", \"$UNIT_NAME_2\"]}" | grep -q "hello-from-varlink-test-1"
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries "{\"units\": [\"$UNIT_NAME_1\", \"$UNIT_NAME_2\"]}" | grep -q "hello-from-varlink-test-2"

# check priority filter: priority 4 (warning) should include our warning message
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"priority": 4, "limit": 1000}' | grep -q "varlink-test-warning"
# check priority filter: priority 3 (error) should NOT include our warning (priority 4)
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"priority": 3, "limit": 1000}' | grep "varlink-test-warning")

# invalid parameter: limit over 10000 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"limit": 99999}')

# invalid parameter: priority over 7 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"priority": 99}')

# NoEntries error is raised if there is no result
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"units": ["nonexistent-unit-that-should-have-no-entries.service"]}' 2>&1 | grep io.systemd.JournalAccess.NoEntries )
