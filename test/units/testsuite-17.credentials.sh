#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

at_exit() {
    rm -f /run/credstore/udev.rules.50-testme
    rm -rf /run/systemd/system/systemd-udev-load-credentials.service.d
}

trap at_exit EXIT

mkdir -p /run/credstore
cat > /run/credstore/udev.rules.50-testme <<EOF
SUBSYSTEM=="net", OPTIONS="log_level=debug"
EOF

systemctl edit systemd-udev-load-credentials.service --stdin --drop-in=50-testme.conf <<EOF
[Service]
LoadCredential=udev.rules.50-testme
EOF

systemctl restart systemd-udev-load-credentials.service

test -f /run/udev/rules.d/50-testme.rules
diff /run/credstore/udev.rules.50-testme /run/udev/rules.d/50-testme.rules
