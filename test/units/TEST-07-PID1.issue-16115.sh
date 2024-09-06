#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test ExecCondition= does not restart on abnormal or failure
# Issue: https://github.com/systemd/systemd/issues/16115

systemctl start issue16115-repro-1
systemctl start issue16115-repro-2
systemctl start issue16115-repro-3
sleep 5 # wait a bit in case there are restarts so we can count them below

[[ "$(systemctl show issue16115-repro-1 -P NRestarts)" == "0" ]]
[[ "$(systemctl show issue16115-repro-2 -P NRestarts)" == "0" ]]
[[ "$(systemctl show issue16115-repro-3 -P NRestarts)" == "0" ]]
