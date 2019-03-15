#!/bin/bash
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -ex
set -o pipefail

if journalctl -b | grep -e '\.device: Changed plugged -> dead'; then
    exit 1
fi

echo OK > /testok
exit 0
