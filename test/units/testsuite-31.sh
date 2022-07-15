#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if journalctl -b -t systemd --grep '\.device: Changed plugged -> dead'; then
    exit 1
fi

echo OK >/testok
exit 0
