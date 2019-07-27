#!/bin/sh
set -eu

$1 -dM -include linux/input.h - </dev/null | awk '
    /\<(KEY_(MAX|MIN_INTERESTING))|(BTN_(MISC|MOUSE|JOYSTICK|GAMEPAD|DIGI|WHEEL|TRIGGER_HAPPY))\>/  { next }
    /^#define[ \t]+(KEY|BTN)_[^ ]+[ \t]+[0-9BK]/                                                    { print $2 }
'
