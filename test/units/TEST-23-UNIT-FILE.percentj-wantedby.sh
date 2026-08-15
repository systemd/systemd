#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

# Ensure %j Wants directives work
systemd-run --wait \
            --property="Type=oneshot" \
            --property="Wants=TEST-23-UNIT-FILE-specifier-j-wants.service" \
            --property="After=TEST-23-UNIT-FILE-specifier-j-wants.service" \
            true

test -f /tmp/tetsuite-23-specifier-j-done
