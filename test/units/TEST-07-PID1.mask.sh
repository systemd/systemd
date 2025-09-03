#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

at_exit() {
    set +e

    systemctl stop mask-test.service
    rm -f /run/systemd/system/mask-test.service
    systemctl daemon-reload

    rm -f /tmp/should-not-exist
}

trap at_exit EXIT

rm -f /tmp/should-not-exist

mkdir -p /run/systemd/system

cat >/run/systemd/system/mask-test.service <<EOF
[Service]
Type=exec
ExecStart=sleep infinity
ExecStop=touch /tmp/should-not-exist
MountAPIVFS=yes
EOF

systemctl daemon-reload
[[ "$(systemctl is-enabled mask-test.service || :)" == static ]]

systemctl start mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

# Check if mask --now works. Also check if ExecStop= is not executed.
systemctl mask --now mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == masked ]]
[[ "$(systemctl is-active mask-test.service || :)" == inactive ]]
[[ ! -f /tmp/should-not-exist ]]

systemctl unmask mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == static ]]

systemctl start mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

systemctl mask mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == masked ]]
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

# Check if mask --now for already masked unit stops the service.
systemctl mask --now mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == masked ]]
[[ "$(systemctl is-active mask-test.service || :)" == inactive ]]
[[ ! -f /tmp/should-not-exist ]]

systemctl unmask mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == static ]]

systemctl start mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

systemctl mask mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == masked ]]
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

# Check if already masked unit can be stopped.
systemctl stop mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == inactive ]]
[[ ! -f /tmp/should-not-exist ]]
