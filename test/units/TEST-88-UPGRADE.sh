#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

pkgdir=/usr/host-pkgs

if ! [[ -d $pkgdir ]]; then
    echo "Distro packages not found in $pkgdir" >/skipped
    exit 77
fi

if ! command -v dnf >/dev/null; then
    echo 'dnf not found, skipping test.' >/skipped
    exit 77
fi

minor=$(systemctl --version | awk '/^systemd/{print$2}')
networkd=
unitscmd='systemctl list-units --failed *systemd*'

if [[ $($unitscmd --output json | jq length) -gt 0 ]]; then
    echo 'Systemd failed units found before the test:'
    $unitscmd
    $unitscmd --output json | jq -r '.[].unit' >/tmp/failed-units
fi

check_sd() {
    local unit fail=0 timer1_new timer2_new
    for unit in $($unitscmd --output json | jq -r '.[].unit'); do
        if ! grep -sxqF "$unit" /tmp/failed-units; then
            fail=1
            systemctl status "$unit"
        fi
    done

    if [[ $fail -eq 1 ]]; then
        echo 'Systemd units above failed after the test!'
    fi

    if [[ -n $networkd ]]; then
        if ! networkctl status; then
            echo 'Networkd failed after the test!'
            fail=1
        fi
    fi

    if ! loginctl list-sessions; then
        echo 'Loginctl failed after the test!'
        fail=1
    fi

    # ignore the systemctl status error code until we sort out
    # https://github.com/systemd/systemd/issues/38214
    systemctl status upgrade_timer_test.{service,timer} || true
    timer1_new=$(systemctl show -P TimersCalendar upgrade_timer_test.timer)
    timer2_new=$(systemctl show -P NextElapseUSecRealtime upgrade_timer_test.timer)

    if [[ "$timer1" != "$timer1_new" ]]; then
        echo "Timer changed unexpectedly: '$timer1' != '$timer1_new'"
        fail=1
    fi
    if [[ "$timer2" != "$timer2_new" ]]; then
        echo "Timer changed unexpectedly: '$timer2' != '$timer2_new'"
        fail=1
    fi

    [[ $fail -eq 0 ]]
}

# Copy the unit in /run so systemd finds it after the downgrade
cp /usr/lib/systemd/tests/testdata/units/TEST-88-UPGRADE.service /run/systemd/system
# Also backup post.sh
cp /usr/lib/systemd/tests/testdata/units/post.sh /tmp/.

now=$(date +%s)
after_2h=$((now + 3600 * 2))
systemd-run --on-calendar="@$after_2h" -u upgrade_timer_test date
timer1=$(systemctl show -P TimersCalendar upgrade_timer_test.timer)
timer2=$(systemctl show -P NextElapseUSecRealtime upgrade_timer_test.timer)

# FIXME: See https://github.com/systemd/systemd/pull/39293
systemctl stop systemd-networkd-resolve-hook.socket || true

dnf downgrade --no-gpgchecks -y --allowerasing --disablerepo '*' "$pkgdir"/distro/*.rpm

# Some distros don't ship networkd, so the test will always fail
if command -v networkctl >/dev/null; then
    networkd=1
fi

newminor=$(systemctl --version | awk '/^systemd/{print$2}')

if [[ $newminor -lt $minor ]]; then
    echo "Downgrade to $newminor was successful."
else
    echo "Downgrade failed. Current version is still $newminor."
    exit 1
fi

# TODO: sanity checks

check_sd

# Finally test the upgrade
dnf -y upgrade --no-gpgchecks --disablerepo '*' "$pkgdir"/devel/*.rpm

# TODO: sanity checks
check_sd

# Restore post.sh
mkdir -p /usr/lib/systemd/tests/testdata/units
mv /tmp/post.sh /usr/lib/systemd/tests/testdata/units/.

touch /testok
