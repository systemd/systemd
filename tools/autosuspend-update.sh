#!/bin/sh
set -eu

cd "$1"

(curl -L 'https://chromium.googlesource.com/chromiumos/platform2/+/master/power_manager/udev/gen_autosuspend_rules.py?format=TEXT'; echo) \
    | base64 -d > gen_autosuspend_rules.py
