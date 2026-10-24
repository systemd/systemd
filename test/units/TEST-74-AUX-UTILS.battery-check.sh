#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

if [[ ! -x /usr/lib/systemd/systemd-battery-check ]]; then
    echo "systemd-battery-check is not installed, skipping test."
    exit 77
fi

/usr/lib/systemd/systemd-battery-check --help
/usr/lib/systemd/systemd-battery-check --version

/usr/lib/systemd/systemd-battery-check || :
