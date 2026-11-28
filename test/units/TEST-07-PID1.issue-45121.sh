#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# A drop-in or system.conf masked by a symlink to /dev/null made PID 1 ignore its whole configuration.
# Issue: https://github.com/systemd/systemd/issues/45121

MAIN=/etc/systemd/system.conf
MASKED=99-issue-45121-masked.conf
DROPIN=99-issue-45121.conf
START_TIMEOUT="$(systemctl show -P DefaultTimeoutStartUSec)"
STOP_TIMEOUT="$(systemctl show -P DefaultTimeoutStopUSec)"

cleanup() {
    rm -f /run/systemd/system.conf.d/{"$MASKED","$DROPIN"} /etc/systemd/system.conf.d/"$MASKED"
    if [[ -e "$MAIN.issue-45121" ]]; then
        mv -f "$MAIN.issue-45121" "$MAIN"
    else
        rm -f "$MAIN"
    fi
    systemctl daemon-reload

    assert_eq "$(systemctl show -P DefaultTimeoutStartUSec)" "$START_TIMEOUT"
    assert_eq "$(systemctl show -P DefaultTimeoutStopUSec)" "$STOP_TIMEOUT"
}

if [[ -e "$MAIN" ]]; then
    cp -a "$MAIN" "$MAIN.issue-45121"
fi
trap cleanup EXIT

mkdir -p /run/systemd/system.conf.d /etc/systemd/system.conf.d
printf '[Manager]\nDefaultTimeoutStartSec=3min\n' >/run/systemd/system.conf.d/"$MASKED"
printf '[Manager]\nDefaultTimeoutStopSec=4min\n' >/run/systemd/system.conf.d/"$DROPIN"

# A drop-in masked in a directory of higher priority is skipped, the other one still applies
ln -s /dev/null /etc/systemd/system.conf.d/"$MASKED"
systemctl daemon-reload
assert_eq "$(systemctl show -P DefaultTimeoutStartUSec)" "$START_TIMEOUT"
assert_eq "$(systemctl show -P DefaultTimeoutStopUSec)" 4min

# With the main file masked instead, both drop-ins apply
rm /etc/systemd/system.conf.d/"$MASKED"
ln -sf /dev/null "$MAIN"
systemctl daemon-reload
assert_eq "$(systemctl show -P DefaultTimeoutStartUSec)" 3min
assert_eq "$(systemctl show -P DefaultTimeoutStopUSec)" 4min
