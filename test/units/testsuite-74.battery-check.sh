#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemd-battery-check --help
systemd-battery-check --version

systemd-battery-check || :
