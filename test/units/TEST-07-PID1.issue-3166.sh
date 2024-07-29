#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Service doesn't enter the "failed" state
# Issue: https://github.com/systemd/systemd/issues/3166

systemctl --no-block start issue3166-fail-on-restart.service
active_state="$(systemctl show --value --property ActiveState issue3166-fail-on-restart.service)"
while [[ "$active_state" == "activating" || "$active_state" =~ ^(in)?active$ ]]; do
    sleep .5
    active_state="$(systemctl show --value --property ActiveState issue3166-fail-on-restart.service)"
done
systemctl is-failed issue3166-fail-on-restart.service || exit 1
[[ "$(systemctl show --value --property NRestarts issue3166-fail-on-restart.service)" -le 3 ]] || exit 1
