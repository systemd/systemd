#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ux
set -o pipefail

systemd-run -p PrivateBPF=no --wait true
if ! systemd-run -p PrivateBPF=yes --wait true; then
        journalctl --no-pager -p warning
        exit 1
fi
