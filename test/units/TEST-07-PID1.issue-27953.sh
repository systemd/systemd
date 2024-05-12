#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check if the unit doesn't remain in active state after the main PID exits
# Issue: https://github.com/systemd/systemd/issues/27953

systemctl start issue27953.service
timeout 10 sh -c 'while systemctl is-active issue27953.service; do sleep .5; done'
[[ "$(systemctl show -P ExitType issue27953.service)" == main ]]
