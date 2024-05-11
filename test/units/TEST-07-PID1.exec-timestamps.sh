#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that timestamps of a Type=notify service are consistent

systemd-run --service-type notify --property NotifyAccess=all --unit notify.service --wait sh -c 'systemd-notify --ready; exit 1' || :

start=$(systemctl show --property=ExecMainStartTimestampMonotonic --value notify.service)
handoff=$(systemctl show --property=ExecMainHandoffTimestampMonotonic --value notify.service)
active=$(systemctl show --property=ActiveEnterTimestampMonotonic --value notify.service)
exit=$(systemctl show --property=ExecMainExitTimestampMonotonic --value notify.service)

[[ $start -le $handoff ]]
[[ $handoff -le $active ]]
[[ $active -le $exit ]]
