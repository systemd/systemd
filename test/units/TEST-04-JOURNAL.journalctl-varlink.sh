#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

VARLINK_SOCKET="/run/systemd/io.systemd.JournalAccess"

# Wrapper around varlinkctl that retries up to 3 times when the server returns
# NoEntries to avoid spurious flaky failures
varlinkctl_get_entries() {
    local output rc
    for _ in 1 2 3; do
        output="$(varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries "$@" 2>&1)" && rc=0 || rc=$?
        if [[ $rc -eq 0 ]]; then
            printf '%s\n' "$output"
            return 0
        fi
        if ! grep -q 'io.systemd.JournalAccess.NoEntries' <<<"$output"; then
            printf '%s\n' "$output" >&2
            return $rc
        fi
        journalctl --sync || true
    done
    printf '%s\n' "$output" >&2
    return $rc
}

# ensure the varlink basics work
varlinkctl list-interfaces "$VARLINK_SOCKET" | grep io.systemd.JournalAccess
varlinkctl introspect "$VARLINK_SOCKET" | grep "method GetEntries("

# lets start with a basic log entry
TAG="$(systemd-id128 new)"
echo "varlink-test-message" | systemd-cat -t "$TAG"
systemd-cat -t "$TAG" -p warning echo "varlink-test-warning"
journalctl --sync

# most basic call works
varlinkctl_get_entries '{}' | jq --seq .
# validate the JSON has some basic properties (similar to journalctls json output)
varlinkctl_get_entries '{}' | jq --seq '.entry | {MESSAGE, PRIORITY, _UID}'

# check that default limit works (100), we don't know how many entries we have so we just check
# bounds
ENTRIES=$(varlinkctl_get_entries '{}' | wc -l)
test "$ENTRIES" -gt 0
test "$ENTRIES" -le 100

# check explicit limit
ENTRIES=$(varlinkctl_get_entries '{"limit": 3}' | wc -l)
test "$ENTRIES" -le 3

# check unit filter: use transient units to get deterministic results
UNIT_NAME_1="test-journalctl-varlink-1-$RANDOM.service"
systemd-run --unit="$UNIT_NAME_1" --wait bash -c 'echo hello-from-varlink-test-1'
UNIT_NAME_2="test-journalctl-varlink-2-$RANDOM.service"
systemd-run --unit="$UNIT_NAME_2" --wait bash -c 'echo hello-from-varlink-test-2'
journalctl --sync

# single unit filter
SINGLE_OUTPUT="$(varlinkctl_get_entries "{\"units\": [\"$UNIT_NAME_1\"]}")"
grep "hello-from-varlink-test-1" >/dev/null <<<"$SINGLE_OUTPUT"
(! grep "hello-from-varlink-test-2" >/dev/null <<<"$SINGLE_OUTPUT")
# multi unit filter
MULTI_OUTPUT="$(varlinkctl_get_entries "{\"units\": [\"$UNIT_NAME_1\", \"$UNIT_NAME_2\"]}")"
grep "hello-from-varlink-test-1" >/dev/null <<<"$MULTI_OUTPUT"
grep "hello-from-varlink-test-2" >/dev/null <<<"$MULTI_OUTPUT"

# check priority filter: priority 4 (warning) should include our warning message
varlinkctl_get_entries '{"priority": 4, "limit": 1000}' | grep "varlink-test-warning" >/dev/null
# check priority filter: priority 3 (error) should NOT include our warning (priority 4)
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"priority": 3, "limit": 1000}' | grep "varlink-test-warning")

# invalid parameter: limit over 10000 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"limit": 99999}')

# invalid parameter: priority over 7 should fail
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"priority": 99}')

# NoEntries error is raised if there is no result
(! varlinkctl call --more "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries '{"units": ["nonexistent-unit-that-should-have-no-entries.service"]}' 2>&1 | grep io.systemd.JournalAccess.NoEntries )

# follow mode: after the backlog the call stays open and new entries are streamed
FOLLOW_OUT="$(mktemp)"
FOLLOW_UNIT_OUT="$(mktemp)"
FOLLOW_PID=""
FOLLOW_UNIT_PID=""
cleanup_follow() {
    [[ -n "$FOLLOW_PID" ]] && kill "$FOLLOW_PID" 2>/dev/null || :
    [[ -n "$FOLLOW_UNIT_PID" ]] && kill "$FOLLOW_UNIT_PID" 2>/dev/null || :
    rm -f "$FOLLOW_OUT" "$FOLLOW_UNIT_OUT"
}
trap cleanup_follow EXIT

# -E is short for --more --timeout=infinity: without it varlinkctl gives up on quiet streams after 45s.
# Filter by our own unit: with debug logging the server instance traces every message it sends into
# the very journal it is following, feeding back on itself until the output queue limit (-ENOBUFS)
# kills the connection.
varlinkctl call -E "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries \
    '{"follow": true, "limit": 2, "units": ["TEST-04-JOURNAL.service"]}' >"$FOLLOW_OUT" &
FOLLOW_PID=$!

# the backlog arrives quickly and the call does not complete
timeout 30 bash -c "until [[ \$(wc -l <'$FOLLOW_OUT') -ge 2 ]]; do sleep .5; done"
kill -0 "$FOLLOW_PID"

# new entries are pushed into the stream as they are logged
echo "varlink-follow-live-1" | systemd-cat -t "$TAG"
journalctl --sync
timeout 30 bash -c "until grep -q varlink-follow-live-1 '$FOLLOW_OUT'; do sleep .5; done"
echo "varlink-follow-live-2" | systemd-cat -t "$TAG"
journalctl --sync
timeout 30 bash -c "until grep -q varlink-follow-live-2 '$FOLLOW_OUT'; do sleep .5; done"
kill -0 "$FOLLOW_PID"

# follow composes with filters, and an empty backlog does not complete the call
FOLLOW_UNIT="test-journalctl-varlink-follow-$RANDOM.service"
varlinkctl call -E "$VARLINK_SOCKET" io.systemd.JournalAccess.GetEntries "{\"follow\": true, \"units\": [\"$FOLLOW_UNIT\"]}" >"$FOLLOW_UNIT_OUT" &
FOLLOW_UNIT_PID=$!
sleep 1
kill -0 "$FOLLOW_UNIT_PID"
test ! -s "$FOLLOW_UNIT_OUT"

systemd-run --unit="$FOLLOW_UNIT" --wait bash -c 'echo hello-from-follow-test'
journalctl --sync
timeout 30 bash -c "until grep -q hello-from-follow-test '$FOLLOW_UNIT_OUT'; do sleep .5; done"
(! grep -q varlink-follow-live-1 "$FOLLOW_UNIT_OUT")

# on client disconnect the socket-activated server instances exit again (exit-on-idle)
kill "$FOLLOW_PID" "$FOLLOW_UNIT_PID"
FOLLOW_PID=""
FOLLOW_UNIT_PID=""
timeout 30 bash -c 'until [[ $(systemctl list-units --no-legend --plain "systemd-journalctl@*.service" | wc -l) -eq 0 ]]; do sleep .5; done'
