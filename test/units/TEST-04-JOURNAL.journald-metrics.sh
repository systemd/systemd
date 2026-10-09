#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# systemd-journald counts received log messages by priority and by transport, and exposes the counters via
# io.systemd.Metrics on a socket in /run/systemd/report/.
SOCKET="/run/systemd/report/io.systemd.JournalDaemon"

# Some distros don't enable the socket by default. journald only picks up the socket when it is started, hence
# restart it if we had to start the socket.
if ! systemctl is-active --quiet systemd-journald-metrics.socket; then
    systemctl start systemd-journald-metrics.socket
    systemctl restart systemd-journald.service
fi
test -S "$SOCKET"
test -f /run/systemd/journal/counters

varlinkctl list-interfaces "$SOCKET" | grep io.systemd.Metrics >/dev/null

DESCRIBE="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.Describe '{}')"
jq --seq -r '.name' <<<"$DESCRIBE" | grep '^io.systemd.JournalDaemon.MessagesByPriority$' >/dev/null
jq --seq -r '.name' <<<"$DESCRIBE" | grep '^io.systemd.JournalDaemon.MessagesByTransport$' >/dev/null

# Prints the counter value of the specified family and field
counter() {
    varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}' |
        jq --seq -r --arg n "io.systemd.JournalDaemon.$1" --arg k "$2" --arg v "$3" \
           'select(.name == $n and .fields[$k] == $v) | .value | tostring'
}

# One row per priority and per transport
LIST="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"
for p in emerg alert crit err warning notice info debug; do
    [ "$(jq --seq -r --arg p "$p" 'select(.name == "io.systemd.JournalDaemon.MessagesByPriority" and .fields.priority == $p) | .name' <<<"$LIST" | wc -l)" -eq 1 ]
done
for t in syslog journal stdout audit kernel; do
    [ "$(jq --seq -r --arg t "$t" 'select(.name == "io.systemd.JournalDaemon.MessagesByTransport" and .fields.transport == $t) | .name' <<<"$LIST" | wc -l)" -eq 1 ]
done
[ "$(jq --seq -r 'select(.name == "io.systemd.JournalDaemon.MessagesByPriority") | .name' <<<"$LIST" | wc -l)" -eq 8 ]
[ "$(jq --seq -r 'select(.name == "io.systemd.JournalDaemon.MessagesByTransport") | .name' <<<"$LIST" | wc -l)" -eq 5 ]

TAG="$(systemd-id128 new)"
N=10

# Other things are logging concurrently, hence we can only check that the counters increased at least by the
# number of messages we sent.

# stdout transport
BEFORE_STDOUT="$(counter MessagesByTransport transport stdout)"
BEFORE_WARNING="$(counter MessagesByPriority priority warning)"
for ((i = 0; i < N; i++)); do
    echo "metrics-stdout-$TAG-$i"
done | systemd-cat -t "metrics-$TAG" -p warning
journalctl --sync
(( $(counter MessagesByTransport transport stdout) >= BEFORE_STDOUT + N ))
(( $(counter MessagesByPriority priority warning) >= BEFORE_WARNING + N ))

# syslog transport
BEFORE_SYSLOG="$(counter MessagesByTransport transport syslog)"
BEFORE_ERR="$(counter MessagesByPriority priority err)"
for ((i = 0; i < N; i++)); do
    logger -t "metrics-$TAG" -p user.err "metrics-syslog-$TAG-$i"
done
journalctl --sync
(( $(counter MessagesByTransport transport syslog) >= BEFORE_SYSLOG + N ))
(( $(counter MessagesByPriority priority err) >= BEFORE_ERR + N ))

# native transport (not using "logger --journald" here, since busybox' logger doesn't support it)
BEFORE_JOURNAL="$(counter MessagesByTransport transport journal)"
BEFORE_ALERT="$(counter MessagesByPriority priority alert)"
for ((i = 0; i < N; i++)); do
    printf 'MESSAGE=metrics-native-%s-%s\nPRIORITY=1\nSYSLOG_IDENTIFIER=metrics-%s\n' "$TAG" "$i" "$TAG" | socat -t 5 - UNIX-SENDTO:/run/systemd/journal/socket
done
journalctl --sync
(( $(counter MessagesByTransport transport journal) >= BEFORE_JOURNAL + N ))
(( $(counter MessagesByPriority priority alert) >= BEFORE_ALERT + N ))

# kernel transport (/dev/kmsg is not available in containers)
if ! systemd-detect-virt --quiet --container; then
    BEFORE_KERNEL="$(counter MessagesByTransport transport kernel)"
    BEFORE_CRIT="$(counter MessagesByPriority priority crit)"
    for ((i = 0; i < N; i++)); do
        echo "<2>metrics-kernel-$TAG-$i" >/dev/kmsg
    done
    journalctl --sync
    (( $(counter MessagesByTransport transport kernel) >= BEFORE_KERNEL + N ))
    (( $(counter MessagesByPriority priority crit) >= BEFORE_CRIT + N ))
fi

# Messages suppressed via LogLevelMax= are counted nonetheless
BEFORE_DEBUG="$(counter MessagesByPriority priority debug)"
systemd-run --wait -p LogLevelMax=info -p StandardOutput=journal -p SyslogIdentifier="suppressed-$TAG" \
    bash -c "for ((i = 0; i < $N; i++)); do echo \"<7>metrics-suppressed-$TAG-\$i\"; done"
journalctl --sync
(( $(counter MessagesByPriority priority debug) >= BEFORE_DEBUG + N ))
[ -z "$(journalctl -q -o cat -t "suppressed-$TAG")" ]

# The counters survive a restart of journald
LIST_BEFORE="$(varlinkctl --more call "$SOCKET" io.systemd.Metrics.List '{}')"
systemctl restart systemd-journald.service
for t in syslog journal stdout audit kernel; do
    before="$(jq --seq -r --arg t "$t" 'select(.name == "io.systemd.JournalDaemon.MessagesByTransport" and .fields.transport == $t) | .value | tostring' <<<"$LIST_BEFORE")"
    (( $(counter MessagesByTransport transport "$t") >= before ))
done
for p in emerg alert crit err warning notice info debug; do
    before="$(jq --seq -r --arg p "$p" 'select(.name == "io.systemd.JournalDaemon.MessagesByPriority" and .fields.priority == $p) | .value | tostring' <<<"$LIST_BEFORE")"
    (( $(counter MessagesByPriority priority "$p") >= before ))
done
