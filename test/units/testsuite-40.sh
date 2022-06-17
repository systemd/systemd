#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

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
    systemd-run --unit="$c" -r -p "Type=oneshot" -p "${property[$c]}=:/bin/echo \${$c}" /bin/true
    systemctl show -p "${property[$c]}" "$c" | grep -F "path=/bin/echo ; argv[]=/bin/echo \${$c} ; ignore_errors=no"
    systemctl show -p "${property[$c]}Ex" "$c" | grep -F "path=/bin/echo ; argv[]=/bin/echo \${$c} ; flags=no-env-expand"
done

declare -A property_ex

property_ex[1_one_ex]=ExecConditionEx
property_ex[2_two_ex]=ExecStartPreEx
property_ex[3_three_ex]=ExecStartEx
property_ex[4_four_ex]=ExecStartPostEx
property_ex[5_five_ex]=ExecReloadEx
property_ex[6_six_ex]=ExecStopEx
property_ex[7_seven_ex]=ExecStopPostEx

for c in "${!property_ex[@]}"; do
    systemd-run --unit="$c" -r -p "Type=oneshot" -p "${property_ex[$c]}=:/bin/echo \${$c}" /bin/true
    systemctl show -p "${property_ex[$c]%??}" "$c" | grep -F "path=/bin/echo ; argv[]=/bin/echo \${$c} ; ignore_errors=no"
    systemctl show -p "${property_ex[$c]}" "$c" | grep -F "path=/bin/echo ; argv[]=/bin/echo \${$c} ; flags=no-env-expand"
done

systemd-analyze log-level info

echo OK >/testok

exit 0
