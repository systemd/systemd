#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# For issue #39247.

at_exit() {
    set +e

    rm -rf /run/systemd/system/systemd-resolved.service.d/
    systemctl daemon-reload
    systemctl restart systemd-resolved.service
}

trap at_exit EXIT

mkdir -p /run/systemd/system/systemd-resolved.service.d/
cat >/run/systemd/system/systemd-resolved.service.d/99-start-limit.conf <<EOF
[Unit]
StartLimitBurst=5
StartLimitInterval=100

[Service]
ExecStopPost=sleep 10
EOF

systemctl daemon-reload
systemctl restart systemd-resolved.service
systemctl reset-failed systemd-resolved.service
systemctl status --no-pager systemd-resolved.service
systemctl show systemd-resolved.service | grep StartLimit

for i in {1..5}; do
    echo "Start #$i"

    systemctl stop --no-block systemd-resolved.service
    # Wait for systemd-resolved in ExecStart= being stopped.
    # shellcheck disable=SC2016
    timeout 10 bash -c 'until [[ "$(systemctl show --property=MainPID --value systemd-resolved.service)" == 0 ]]; do sleep 0.1; done'
    if ! resolvectl; then
        journalctl -o short-monotonic --no-hostname --no-pager -u systemd-resolved.service -n 15
        exit 1
    fi
    systemctl is-active systemd-resolved.service
done
