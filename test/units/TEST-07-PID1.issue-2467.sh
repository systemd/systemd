#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Don't start services every few ms if condition fails
# Issue: https://github.com/systemd/systemd/issues/2467

rm -f /tmp/nonexistent
systemctl start issue2467.socket
ncat -i20 -w20 -U /run/test.ctl || :

# TriggerLimitIntervalSec= by default is set to 2s. A "sleep 10" should give
# systemd enough time even on slower machines, to reach the trigger limit.
# shellcheck disable=SC2016
timeout 10 bash -c 'until [[ "$(systemctl show issue2467.socket -P ActiveState)" == failed ]]; do sleep .5; done'
[[ "$(systemctl show issue2467.socket -P Result)" == trigger-limit-hit ]]
