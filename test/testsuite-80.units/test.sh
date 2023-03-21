#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemd-notify --status="Test starts, waiting for 5 seconds"
sleep 5

(
    systemd-notify --pid=auto
    systemd-notify "NOTIFYACCESS=main"

    systemd-notify --status="Sending READY=1 in an unpriviledged process"
    ( systemd-notify --ready )
    sleep 10

    systemd-notify --pid="$$"
)

systemd-notify --ready --status="OK"
systemd-notify "NOTIFYACCESS=none"
sleep infinity
