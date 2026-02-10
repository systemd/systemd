#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

VARLINK_SOCKET="/run/systemd/io.systemd.Journalctl"

# ensure the varlink basics work
varlinkctl list-interfaces "$VARLINK_SOCKET" | grep io.systemd.Journalctl
varlinkctl introspect "$VARLINK_SOCKET" | grep "method GetEntries("

# lets start with a basic log entry
TAG="$(systemd-id128 new)"
echo "varlink-test-message" | systemd-cat -t "$TAG"
systemd-cat -t "$TAG" -p warning echo "varlink-test-warning"
journalctl --sync

# most basic call works
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{}' | jq --seq .
# validate the JSON has some basic properties (similar to journalctls json output)
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{}' | jq --seq '.entry | {MESSAGE, PRIORITY, _UID}'

# check that default limit works (100), we don't know how many entries we have so we just check
# bounds
ENTRIES=$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{}' | wc -l)
test "$ENTRIES" -gt 0
test "$ENTRIES" -le 100

# check explit limit
ENTRIES=$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"limit": 3}' | wc -l)
test "$ENTRIES" -le 3

# check unit filter: one filter unit works
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"units": ["systemd-logind.service"]}' | jq --seq .entry._SYSTEMD_UNIT
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"units": ["systemd-logind.service"]}' | jq --seq -s -e 'all(.entry._SYSTEMD_UNIT == "systemd-logind.service")'
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"units": ["systemd-logind.service", "systemd-oomd.service"]}' | jq --seq -s -e 'all(.[]; .entry._SYSTEMD_UNIT | IN("systemd-logind.service", "systemd-oomd.service"))'

# check priority filter: priority 4 (warning) should include our warning message
varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"priority": 4, "limit": 1000}' | grep -q "varlink-test-warning"
# check priority filter: priority 3 (error) should NOT include our warning (priority 4)
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"priority": 3, "limit": 1000}' | grep "varlink-test-warning")

# invalid parameter: limit over 10000 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"limit": 99999}')

# invalid parameter: priority over 7 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"priority": 99}')

# NoEntries error is raised if there is no result
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.Journalctl.GetEntries '{"units": ["nonexistent-unit-that-should-have-no-entries.service"]}' 2>&1 | grep io.systemd.Journalctl.NoEntries )
