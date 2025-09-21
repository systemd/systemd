#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test ExecXYZEx= service unit dbus hookups

systemd-analyze log-level debug

declare -A property

property[1_one]=ExecCondition
property[2_two]=ExecStartPre
property[3_three]=ExecStart
property[4_four]=ExecStartPost
property[5_five]=ExecReload
property[6_six]=ExecStop
property[7_seven]=ExecStopPost

# These should all get upgraded to the corresponding Ex property as the non-Ex variant
# does not support the ":" prefix (no-env-expand).
for c in "${!property[@]}"; do
    systemd-run --unit="$c" -r -p "Type=oneshot" -p "${property[$c]}=:echo \${$c}" true
    systemctl show -p "${property[$c]}" "$c" | grep -F "path=echo ; argv[]=echo \${$c} ; ignore_errors=no"
    systemctl show -p "${property[$c]}Ex" "$c" | grep -F "path=echo ; argv[]=echo \${$c} ; flags=no-env-expand"
done

# Ex names on the commandline are supported for backward compat.
for c in "${!property[@]}"; do
    systemd-run --unit="${c}_ex" -r -p "Type=oneshot" -p "${property[$c]}Ex=:echo \${$c}" true
    systemctl show -p "${property[$c]}" "$c" | grep -F "path=echo ; argv[]=echo \${$c} ; ignore_errors=no"
    systemctl show -p "${property[$c]}Ex" "$c" | grep -F "path=echo ; argv[]=echo \${$c} ; flags=no-env-expand"
done

systemd-analyze log-level info
