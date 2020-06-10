#!/usr/bin/env bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

systemctl start repro-1
systemctl start repro-2
sleep 5 # wait a bit in case there are restarts so we can count them below

[[ "$(systemctl show repro-1 --value -p NRestarts)" == "0" ]]
[[ "$(systemctl show repro-2 --value -p NRestarts)" == "0" ]]

systemd-analyze log-level info

echo OK > /testok

exit 0
