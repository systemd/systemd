#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl stop systemd-journald.service
systemd-cat date

# shellcheck disable=SC2016
timeout 30 bash -xec 'until test "$(systemctl show -p SubState --value systemd-journald.service)" = "running"; do sleep 1; done'
