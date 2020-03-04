#!/usr/bin/env bash
set -e
set -o pipefail

if journalctl -b -t systemd --grep '\.device: Changed plugged -> dead'; then
    exit 1
fi

echo OK > /testok
exit 0
