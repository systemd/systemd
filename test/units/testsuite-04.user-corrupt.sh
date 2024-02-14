#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

mkdir -p /etc/sudoers.d/
echo "testuser ALL=(ALL) NOPASSWD: ALL" >/etc/sudoers.d/testuser

REPRO_SCRIPT="$(mktemp)"

cat >"$REPRO_SCRIPT" <<\EOF
#!/bin/bash
set -eux
set -o pipefail

journalctl --rotate --vacuum-files=1
# Nuke all archived journals, so we start with a clean slate
rm -f /var/log/journal/$(</etc/machine-id)/system@*.journal
rm -f /var/log/journal/$(</etc/machine-id)/user-*@*.journal
journalctl --header | grep path

for i in {0..10}; do
    journalctl --rotate
    journalctl --sync
    SYSTEMD_LOG_LEVEL=debug journalctl -n1 -q
    (! journalctl -n0 -q |& grep corrupted)
done
EOF
chmod +x "$REPRO_SCRIPT"

systemd-run --wait --pipe --user -M testuser@ -- sudo "$REPRO_SCRIPT"
