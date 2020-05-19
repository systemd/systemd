#!/usr/bin/env bash
set -x

systemctl start fail-on-restart.service
active_state=$(systemctl show --value --property ActiveState fail-on-restart.service)
while [[ "$active_state" == "activating" || "$active_state" == "active" ]]; do
    sleep 1
    active_state=$(systemctl show --value --property ActiveState fail-on-restart.service)
done
systemctl is-failed fail-on-restart.service || exit 1
touch /testok
