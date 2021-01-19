#!/bin/sh
set -eu

cd "$1"

(curl --fail -L 'https://chromium.googlesource.com/chromiumos/platform2/+/master/power_manager/udev/gen_autosuspend_rules.py?format=TEXT'; echo) \
    | base64 -d > tools/chromiumos/gen_autosuspend_rules.py

(cat <<%EOF
# This file is part of systemd.
#
# Pulled from libfprint upstream in order to autosuspend fingerprint readers
#
%EOF
curl -L 'https://gitlab.freedesktop.org/libfprint/libfprint/-/jobs/artifacts/master/raw/60-autosuspend-libfprint.hwdb?job=build') \
    > hwdb.d/60-autosuspend-libfprint.hwdb
