#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu
set -o pipefail

CC=${1:?}
shift

$CC -dM -include linux/input.h "$@" - </dev/null | awk '
    /\<(KEY_(MAX|MIN_INTERESTING))|(BTN_(MISC|MOUSE|JOYSTICK|GAMEPAD|DIGI|WHEEL|TRIGGER_HAPPY))\>/  { next }
    /^#define[ \t]+(KEY|BTN)_[^ ]+[ \t]+[0-9BK]/                                                    { print $2 }
'
