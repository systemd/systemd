#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# https://bugzilla.redhat.com/show_bug.cgi?id=2183546
mkdir /run/systemd/system/systemd-journald.service.d
MACHINE_ID="$(</etc/machine-id)"

mkdir -p /run/systemd/journald.conf.d
cat <<EOF >/run/systemd/journald.conf.d/compress.conf
[Journal]
Compress=yes
EOF

# Reset the start-limit counters, as we're going to restart journald a couple of times
systemctl reset-failed systemd-journald.service

for c in NONE XZ LZ4 ZSTD; do
    cat >/run/systemd/system/systemd-journald.service.d/compress.conf <<EOF
[Service]
Environment=SYSTEMD_JOURNAL_COMPRESS=${c}
EOF
    systemctl daemon-reload
    systemctl restart systemd-journald.service
    journalctl --rotate

    ID="$(systemd-id128 new)"
    systemd-cat -t "$ID" /bin/bash -c "for ((i=0;i<100;i++)); do echo -n hoge with ${c}; done; echo"
    journalctl --sync
    timeout 10 bash -c "until SYSTEMD_LOG_LEVEL=debug journalctl --verify --quiet --file /var/log/journal/$MACHINE_ID/system.journal 2>&1 | grep -q -F 'compress=${c}'; do sleep .5; done"

    # $SYSTEMD_JOURNAL_COMPRESS= also works for journal-remote
    if [[ -x /usr/lib/systemd/systemd-journal-remote ]]; then
        for cc in NONE XZ LZ4 ZSTD; do
            rm -f /tmp/foo.journal
            SYSTEMD_JOURNAL_COMPRESS="${cc}" /usr/lib/systemd/systemd-journal-remote --split-mode=none -o /tmp/foo.journal --getter="journalctl -b -o export -t $ID"
            SYSTEMD_LOG_LEVEL=debug journalctl --verify --quiet --file /tmp/foo.journal 2>&1 | grep -q -F "compress=${cc}"
            journalctl -t "$ID" -o cat --file /tmp/foo.journal | grep -q -F "hoge with ${c}"
        done
    fi
done

rm /run/systemd/journald.conf.d/compress.conf
rm /run/systemd/system/systemd-journald.service.d/compress.conf
systemctl daemon-reload
systemctl restart systemd-journald.service
systemctl reset-failed systemd-journald.service
journalctl --rotate
