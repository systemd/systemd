#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

at_exit() {
    set +e

    systemctl stop mask-test.service
    rm -rf /run/systemd/system/mask-test.service*
    systemctl daemon-reload

    rm -f /tmp/should-not-exist-by-*
}

trap at_exit EXIT

rm -f /tmp/should-not-exist-by-*

mkdir -p /run/systemd/system/mask-test.service.d

cat >/run/systemd/system/mask-test.service <<EOF
[Service]
Type=exec
ExecStart=sleep infinity
ExecStop=touch /tmp/should-not-exist-by-main
EOF

# Check if ExecStop= and friends in a masked unit are not executed even defined
# in drop-in. See issue #38802.
cat >/run/systemd/system/mask-test.service.d/10-stop.conf <<EOF
[Service]
ExecStop=touch /tmp/should-not-exist-by-dropin
EOF

systemctl daemon-reload
[[ "$(systemctl is-enabled mask-test.service || :)" == static ]]

systemctl start mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

# When not masked, of course ExecStop= are executed.
systemctl stop mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == inactive ]]
[[ -f /tmp/should-not-exist-by-main ]]
[[ -f /tmp/should-not-exist-by-dropin ]]
rm -f /tmp/should-not-exist-by-*

systemctl start mask-test.service
[[ "$(systemctl is-active mask-test.service || :)" == active ]]

# Check if mask --now works and ExecStop= are not executed.
systemctl mask --now mask-test.service
[[ "$(systemctl is-enabled mask-test.service || :)" == masked ]]
[[ "$(systemctl is-active mask-test.service || :)" == inactive ]]
[[ ! -f /tmp/should-not-exist-by-main ]]
[[ ! -f /tmp/should-not-exist-by-dropin ]]

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
[[ ! -f /tmp/should-not-exist-by-main ]]
[[ ! -f /tmp/should-not-exist-by-dropin ]]

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
[[ ! -f /tmp/should-not-exist-by-main ]]
[[ ! -f /tmp/should-not-exist-by-dropin ]]
