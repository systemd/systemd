#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

systemd-notify --status="Test starts, waiting for 5 seconds"
sleep 5

(
    systemd-notify --status="Setting MAINPID and NOTIFYACCESS in subshell"
    systemd-notify "MAINPID=${BASHPID}"
    systemd-notify "NOTIFYACCESS=main"

    ( ! systemd-notify --ready )

    systemd-notify --status="Resetting MAINPID to parent shell"
    systemd-notify "MAINPID=$$"
)

systemd-notify --ready --status="OK"
sleep infinity
