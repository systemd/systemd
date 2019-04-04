#!/bin/bash
set -ex
set -o pipefail

if journalctl -b | grep -e '\.device: Changed plugged -> dead'; then
    exit 1
fi

echo OK > /testok
exit 0
