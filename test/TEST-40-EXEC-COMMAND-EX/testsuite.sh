#!/bin/bash
set -ex
set -o pipefail

systemd-analyze log-level debug
systemd-analyze log-target console

rm -f /test_40_output_ex /test_40_output /test_40_ex_output_ex /test_40_ex_output

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
    systemctl show -p "${property[$c]}Ex" "$c" >> /test_40_output_ex
    systemctl show -p "${property[$c]}" "$c" >> /test_40_output
done

[[ $(grep -c "path=/bin/echo ; argv\[\]=/bin/echo \${[0-9].*} ; flags=no-env-expand" /test_40_output_ex) == "${#property[@]}" ]]

[[ $(grep -c "path=/bin/echo ; argv\[\]=/bin/echo \${[0-9].*} ; ignore_errors=no" /test_40_output) == "${#property[@]}" ]]

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
    systemctl show -p "${property_ex[$c]}" "$c" >> /test_40_ex_output_ex
    systemctl show -p "${property_ex[$c]%??}" "$c" >> /test_40_ex_output
done

[[ $(grep -c "path=/bin/echo ; argv\[\]=/bin/echo \${[0-9].*_ex} ; flags=no-env-expand" /test_40_ex_output_ex) == "${#property_ex[@]}" ]]

[[ $(grep -c "path=/bin/echo ; argv\[\]=/bin/echo \${[0-9].*_ex} ; ignore_errors=no" /test_40_ex_output) == "${#property_ex[@]}" ]]

systemd-analyze log-level info

echo OK > /testok

exit 0
