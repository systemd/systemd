#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh

set -eux
set -o pipefail

# Don't crash without User= set
systemd-run --wait -p UtmpIdentifier=test -p UtmpMode=user true
