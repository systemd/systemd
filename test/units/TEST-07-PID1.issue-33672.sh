#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# systemctl status always shows daemon-reload warning for a masked service with drop-ins
# Issue: https://github.com/systemd/systemd/issues/33672

UNIT=test-23-NeedDaemonReload.service

cleanup() {
    rm -rf /run/systemd/system/"$UNIT" /run/systemd/system/"$UNIT".d
    systemctl daemon-reload
}

trap cleanup EXIT

cat > /run/systemd/system/"$UNIT" <<EOF
[Service]
ExecStart=/usr/bin/true
EOF

mkdir /run/systemd/system/"$UNIT".d
cat > /run/systemd/system/"$UNIT".d/desc.conf <<EOF
[Unit]
Description=Test NeedDaemonReload status of a masked unit with drop-ins
EOF

systemctl daemon-reload
systemctl unmask "$UNIT"
assert_eq "$(systemctl show -P NeedDaemonReload "$UNIT")" no

systemctl mask "$UNIT"
assert_eq "$(systemctl show -P NeedDaemonReload "$UNIT")" no
