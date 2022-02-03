#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl start testsuite-51-repro-1
systemctl start testsuite-51-repro-2
systemctl start testsuite-51-repro-3
sleep 5 # wait a bit in case there are restarts so we can count them below

[[ "$(systemctl show testsuite-51-repro-1 -P NRestarts)" == "0" ]]
[[ "$(systemctl show testsuite-51-repro-2 -P NRestarts)" == "0" ]]
[[ "$(systemctl show testsuite-51-repro-3 -P NRestarts)" == "0" ]]

touch /testok
