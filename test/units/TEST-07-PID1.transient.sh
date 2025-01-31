#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

journalctl --sync
TS="$(date '+%H:%M:%S')"

systemd-run -u hogehoge.service sleep infinity
systemctl daemon-reload
systemctl stop hogehoge.service

journalctl --sync
[[ -z "$(journalctl -b -q --since "$TS" -u hogehoge.service -p notice)" ]]
