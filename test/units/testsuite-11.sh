#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

systemctl --no-block start fail-on-restart.service
active_state=$(systemctl show --value --property ActiveState fail-on-restart.service)
while [[ "$active_state" == "activating" || "$active_state" =~ ^(in)?active$ ]]; do
    sleep .5
    active_state=$(systemctl show --value --property ActiveState fail-on-restart.service)
done
systemctl is-failed fail-on-restart.service || exit 1
[[ "$(systemctl show --value --property NRestarts fail-on-restart.service)" -le 3 ]] || exit 1
touch /testok
