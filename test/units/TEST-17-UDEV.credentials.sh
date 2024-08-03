#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

if [[ $(systemctl is-enabled systemd-udev-load-credentials.service) == not-found ]]; then
    echo "Missing systemd-udev-load-credentials.service"
    exit 0
fi

at_exit() {
    rm -f /run/credstore/udev.*
    rm -f /run/udev/udev.conf.d/*
    rm -f /run/udev/rules.d/*
    rm -rf /run/systemd/system/systemd-udev-load-credentials.service.d
}

trap at_exit EXIT

mkdir -p /run/credstore
cat > /run/credstore/udev.conf.50-testme <<EOF
udev_log=debug
EOF
cat > /run/credstore/udev.rules.50-testme <<EOF
SUBSYSTEM=="net", OPTIONS="log_level=debug"
EOF

systemctl edit systemd-udev-load-credentials.service --stdin --drop-in=50-testme.conf <<EOF
[Service]
LoadCredential=udev.conf.50-testme
LoadCredential=udev.rules.50-testme
EOF

systemctl restart systemd-udev-load-credentials.service

diff /run/credstore/udev.conf.50-testme /run/udev/udev.conf.d/50-testme.conf
diff /run/credstore/udev.rules.50-testme /run/udev/rules.d/50-testme.rules
