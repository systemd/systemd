#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-run -p PrivateBPF=no --wait true
systemd-run -p PrivateBPF=yes --wait true
