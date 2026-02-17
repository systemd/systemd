#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

VARLINK_SOCKET="/run/systemd/io.systemd.Journalctl"

# Write a known log entry we can filter for
TAG="$(systemd-id128 new)"
echo "varlink-test-message" | systemd-cat -t "$TAG"
systemd-cat -t "$TAG" -p warning echo "varlink-test-warning"
journalctl --sync

# Basic introspection
varlinkctl info "$VARLINK_SOCKET"
varlinkctl list-interfaces "$VARLINK_SOCKET"
varlinkctl introspect "$VARLINK_SOCKET" io.systemd.Journalctl

# Basic query - should return entries
varlinkctl call --more --json=pretty "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"limit": 5}' | jq --seq .
# Verify the response contains entry objects with MESSAGE field
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"limit": 5}' | grep -q '"MESSAGE"'

# Default limit (omit limit, should return up to 100)
ENTRIES=$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{}' | wc -l)
test "$ENTRIES" -gt 0
test "$ENTRIES" -le 100

# Explicit limit
ENTRIES=$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"limit": 3}' | wc -l)
test "$ENTRIES" -le 3

# Unit filter - query init.scope, should return something
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"units": ["init.scope"], "limit": 5}' | grep -q '"entry"'

# Priority filter - priority 4 (warning) should include our warning message
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"priority": 4, "limit": 1000}' | grep -q "varlink-test-warning"
# Priority 3 (error) should NOT include our warning (priority 4)
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"priority": 3, "limit": 1000}' | grep "varlink-test-warning")

# Invalid parameter - limit over 10000 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"limit": 99999}')

# Invalid parameter - priority over 7 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"priority": 99}')

# NoEntries sentinel - query for a unit that has no entries
varlinkctl call --more --graceful=io.systemd.Journalctl.NoEntries \
    "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"units": ["nonexistent-unit-that-should-have-no-entries.service"], "limit": 5}'
