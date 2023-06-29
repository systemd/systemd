#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

/usr/lib/systemd/systemd-battery-check --help
/usr/lib/systemd/systemd-battery-check --version

/usr/lib/systemd/systemd-battery-check || :
