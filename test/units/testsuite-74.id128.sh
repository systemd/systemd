#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

systemd-id128 --help
systemd-id128 help
systemd-id128 show
systemd-id128 show --pretty | tail -n10
systemd-id128 show 4f68bce3e8cd4db196e7fbcaf984b709 # root-x86-64
systemd-id128 show --pretty 4f68bce3e8cd4db196e7fbcaf984b709

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
