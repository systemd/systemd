#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Make sure NeedDaemonReload= considers newly created drop-ins.
# Issue: https://github.com/systemd/systemd/issues/31752

UNIT=test-issue-31752.service

cleanup() {
    rm -rf /run/systemd/system/"$UNIT" /run/systemd/system/"$UNIT".d
    systemctl daemon-reload
}

trap cleanup EXIT

cat > /run/systemd/system/"$UNIT" <<EOF
[Service]
ExecStart=/usr/bin/true
RemainAfterExit=yes
EOF

systemctl daemon-reload
systemctl start "$UNIT"
assert_eq "$(systemctl show -P NeedDaemonReload "$UNIT")" no

mkdir /run/systemd/system/"$UNIT".d
cat > /run/systemd/system/"$UNIT".d/desc.conf <<EOF
[Unit]
Description=Test NeedDaemonReload status after creating drop-in
EOF

assert_eq "$(systemctl show -P NeedDaemonReload "$UNIT")" yes

rm /run/systemd/system/"$UNIT".d/desc.conf

assert_eq "$(systemctl show -P NeedDaemonReload "$UNIT")" no
