#!/bin/sh
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex

systemctl=${1:-systemctl}

trap 'rm -rf "$root"' EXIT
root=$(mktemp -dt systemctl-test.XXXXXX)

mkdir -p "$root/etc/systemd/system"
>"$root/etc/systemd/system/test1.service"

EDITOR=cat "$systemctl" --root="$root" edit test1.service
! [ -e "$root/etc/systemd/system/test1.service.d/override.conf" ]

printf '%s\n' 3a '[Service]' 'ExecStart=' . w | EDITOR=ed "$systemctl" --root="$root" edit test1.service
printf '%s\n'    '[Service]' 'ExecStart='     | cmp - "$root/etc/systemd/system/test1.service.d/override.conf"
