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

# The server exposes the io.systemd.Metrics interface (in addition to io.systemd.JournalAccess).
varlinkctl list-interfaces "$SOCKET" | grep io.systemd.Metrics >/dev/null

# Describe must advertise our metric family.
varlinkctl --more call "$SOCKET" io.systemd.Metrics.Describe '{}' |
    grep "io.systemd.Journal.HighPriorityMessage" >/dev/null

# Seed a unique high-priority (err) message right before listing, so it is guaranteed to be among the 10
# most recent matches. We run as root (_UID=0), so it lands in the system journal that the provider reads.
TAG="$(systemd-id128 new)"
systemd-cat -t "high-$TAG" -p err echo "metrics-hiprio-$TAG"
# A low-priority (info) message that must NOT be reported.
systemd-cat -t "info-$TAG" -p info echo "metrics-info-$TAG"
journalctl --sync

LIST="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"

# Output is valid application/json-seq.
jq --seq . >/dev/null <<<"$LIST"

# The err message is reported, carrying the message in .value and the priority in .fields.
# systemd-cat -t sets SYSLOG_IDENTIFIER, which the provider maps to the metric's "object".
[ "$(jq --seq -r --arg o "high-$TAG" 'select(.object == $o) | .value' <<<"$LIST")" = "metrics-hiprio-$TAG" ]
[ "$(jq --seq -r --arg o "high-$TAG" 'select(.object == $o) | .fields.priority' <<<"$LIST")" = "3" ]

# The info message is filtered out (priority below err).
[ -z "$(jq --seq -r --arg o "info-$TAG" 'select(.object == $o) | .value' <<<"$LIST")" ]

# The list is capped at 10. Seed more than that and confirm exactly 10 are returned. (Count raw .name
# lines; jq --seq frames non-string output like `length` with an RS byte, but -r string output is clean.)
for ((i = 0; i < 15; i++)); do
    systemd-cat -t "cap-$TAG" -p err echo "metrics-cap-$TAG-$i"
done
journalctl --sync
LIST="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"
COUNT="$(jq --seq -r '.name' <<<"$LIST" | wc -l)"
test "$COUNT" -eq 10

# A message with non-UTF-8 bytes must be escaped, not dropped or truncated at the first bad byte. cescape()
# leaves the printable ASCII intact, so the readable marker still shows up in the reported .value.
BIN_TAG="$(systemd-id128 new)"
printf '\xff\xfe escape-marker-%s' "$BIN_TAG" | systemd-cat -t "bin-$BIN_TAG" -p err
journalctl --sync
LIST="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"
jq --seq -e --arg o "bin-$BIN_TAG" --arg m "escape-marker-$BIN_TAG" \
    'select(.object == $o) | .value | contains($m)' >/dev/null <<<"$LIST"
