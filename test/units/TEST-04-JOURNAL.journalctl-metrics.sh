#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# journalctl's Varlink server also exposes the io.systemd.Metrics provider that reports the most recent
# high-priority journal messages, socket-activated under /run/systemd/report/.
SOCKET="/run/systemd/report/io.systemd.Journal"

# Ensure the socket is running, as some distros don't enable it by default.
systemctl start systemd-journalctl-metrics.socket
test -S "$SOCKET"

# The report socket serves only io.systemd.Metrics. It must NOT expose io.systemd.JournalAccess, otherwise
# a client could call GetEntries here and read the whole journal.
varlinkctl list-interfaces "$SOCKET" | grep io.systemd.Metrics >/dev/null
if varlinkctl list-interfaces "$SOCKET" | grep io.systemd.JournalAccess >/dev/null; then
    echo "Metrics report socket must not expose io.systemd.JournalAccess" >&2
    exit 1
fi
(! varlinkctl call "$SOCKET" io.systemd.JournalAccess.GetEntries '{}' 2>/dev/null)

# Describe must advertise our metric family.
varlinkctl --more call "$SOCKET" io.systemd.Metrics.Describe '{}' |
    grep "io.systemd.Journal.HighPriorityMessage" >/dev/null

# Seed a unique high-priority (crit) message right before listing, so it is guaranteed to be among the 10
# most recent matches. The service runs with --priority=crit, so the level must be crit or higher. We run
# as root (_UID=0), so it lands in the system journal that the provider reads.
TAG="$(systemd-id128 new)"
systemd-cat -t "high-$TAG" -p crit echo "metrics-hiprio-$TAG"
# A low-priority (info) message that must NOT be reported.
systemd-cat -t "info-$TAG" -p info echo "metrics-info-$TAG"
journalctl --sync

LIST="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"

# Output is valid application/json-seq.
jq --seq . >/dev/null <<<"$LIST"

# The crit message is reported, carrying the message in .value and the fields under their raw journal names
# (journal_entry_to_json()). systemd-cat -t sets SYSLOG_IDENTIFIER, which the provider maps to "object".
[ "$(jq --seq -r --arg o "high-$TAG" 'select(.object == $o) | .value' <<<"$LIST")" = "metrics-hiprio-$TAG" ]
[ "$(jq --seq -r --arg o "high-$TAG" 'select(.object == $o) | .fields.PRIORITY' <<<"$LIST")" = "2" ]

# The info message is filtered out (priority below crit).
[ -z "$(jq --seq -r --arg o "info-$TAG" 'select(.object == $o) | .value' <<<"$LIST")" ]

# The list is capped at 10. Seed more than that and confirm exactly 10 are returned. (Count raw .name
# lines; jq --seq frames non-string output like `length` with an RS byte, but -r string output is clean.)
for ((i = 0; i < 15; i++)); do
    systemd-cat -t "cap-$TAG" -p crit echo "metrics-cap-$TAG-$i"
done
journalctl --sync
LIST="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"
COUNT="$(jq --seq -r '.name' <<<"$LIST" | wc -l)"
test "$COUNT" -eq 10
