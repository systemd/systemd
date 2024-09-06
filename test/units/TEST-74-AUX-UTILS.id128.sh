#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

systemd-id128 --help
systemd-id128 help
systemd-id128 show
systemd-id128 show --pretty | tail
systemd-id128 show --value | tail
systemd-id128 show 4f68bce3e8cd4db196e7fbcaf984b709 # root-x86-64
systemd-id128 show --pretty 4f68bce3e8cd4db196e7fbcaf984b709
systemd-id128 show root-x86-64
systemd-id128 show --pretty root-x86-64
[[ "$(systemd-id128 show 4f68bce3e8cd4db196e7fbcaf984b709)" = "$(systemd-id128 show root-x86-64)" ]]
[[ "$(systemd-id128 show 4f68bce3-e8cd-4db1-96e7-fbcaf984b709)" = "$(systemd-id128 show root-x86-64)" ]]

systemd-id128 show root-x86-64 --app-specific=4f68bce3e8cd4db196e7fbcaf984b709
systemd-id128 show --pretty root-x86-64 --app-specific=4f68bce3e8cd4db196e7fbcaf984b709
[[ "$(systemd-id128 show root-x86-64 --app-specific=4f68bce3e8cd4db196e7fbcaf984b709 -P)" = "8ee5535e7cb14c249e1d28b8dfbb939c" ]]

systemd-id128 show -j
systemd-id128 show --no-pager
systemd-id128 show --json=short
systemd-id128 show --no-legend
systemd-id128 show --no-pager --no-legend
systemd-id128 show root -P -u
[[ -n "$(systemd-id128 var-partition-uuid)" ]]
[[ "$(systemd-id128 var-partition-uuid)" != "4d21b016b53445c2a9fb5c16e091fd2d" ]]

[[ "$(systemd-id128 new | wc -c)" -eq 33 ]]
systemd-id128 new -p
systemd-id128 new -u
systemd-id128 new -a 4f68bce3e8cd4db196e7fbcaf984b709

systemd-id128 machine-id
systemd-id128 machine-id --pretty
systemd-id128 machine-id --uuid
systemd-id128 machine-id --app-specific=4f68bce3e8cd4db196e7fbcaf984b709
assert_eq "$(systemd-id128 machine-id)" "$(</etc/machine-id)"

systemd-id128 boot-id
systemd-id128 boot-id --pretty
systemd-id128 boot-id --uuid
systemd-id128 boot-id --app-specific=4f68bce3e8cd4db196e7fbcaf984b709
assert_eq "$(systemd-id128 boot-id --uuid)" "$(</proc/sys/kernel/random/boot_id)"

# shellcheck disable=SC2016
systemd-run --wait --pipe bash -euxc '[[ $INVOCATION_ID == "$(systemd-id128 invocation-id)" ]]'

(! systemd-id128)
(! systemd-id128 new -a '')
(! systemd-id128 new -a '0')
(! systemd-id128 invocation-id -a 4f68bce3e8cd4db196e7fbcaf984b709)
(! systemd-id128 show '')
(! systemd-id128 show "$(set +x; printf '%0.s0' {0..64})")
