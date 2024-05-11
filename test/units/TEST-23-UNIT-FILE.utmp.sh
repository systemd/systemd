#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

USER="test-23-utmp"

cleanup() {
    userdel "$USER"
}

trap cleanup EXIT
useradd "$USER"

assert_eq "$(systemd-run -qP -p UtmpIdentifier=test -p UtmpMode=user -p User=$USER whoami)" "$USER"
assert_eq "$(systemd-run -qP -p UtmpIdentifier=test -p UtmpMode=user whoami)" "$(whoami)"
