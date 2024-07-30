#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl stop systemd-journald.service
systemd-cat date && sleep 1

if [ ! "$(systemctl show -p SubState --value systemd-journald.service)" = "running" ]; then
        exit 1
fi
