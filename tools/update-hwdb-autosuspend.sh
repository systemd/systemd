#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eu

cd "${1:?}"

(curl --fail -L 'https://chromium.googlesource.com/chromiumos/platform2/+/master/power_manager/udev/gen_autosuspend_rules.py?format=TEXT'; echo) \
    | base64 -d > tools/chromiumos/gen_autosuspend_rules.py

(cat <<%EOF
# This file is part of systemd.
#
# Rules to autosuspend known fingerprint readers (pulled from libfprint).
#
%EOF
curl --fail -L 'https://gitlab.freedesktop.org/libfprint/libfprint/-/raw/master/data/autosuspend.hwdb') \
    > hwdb.d/60-autosuspend-fingerprint-reader.hwdb
