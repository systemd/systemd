#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

unit=test-replaced-transient.service
fragment=/run/systemd/system/$unit
trap 'systemctl stop "$unit" || :; rm -f "$fragment"' EXIT

# While its file is still present the service remains transient across a reload.
systemd-run --unit="$unit" -p Type=exec sleep infinity
systemctl daemon-reload
test "$(systemctl show -P Transient "$unit")" = yes
rm "/run/systemd/transient/$unit"
systemctl daemon-reload
test "$(systemctl show -P Transient "$unit")" = no
test "$(systemctl show -P LoadState "$unit")" = not-found

# The live process keeps the unit in memory. Its next load must read the new regular fragment.
printf '[Service]\nExecStart=true\n' >"$fragment"
test "$(systemctl show -P FragmentPath "$unit")" = "$fragment"
systemctl stop "$unit"
test -f "$fragment"
