#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

sleep infinity &
echo $! >/run/leakedtestpid
systemd-notify --ready
wait $!
