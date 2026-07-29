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

if command -v dnf >/dev/null; then
    package_extension=rpm
    downgrade=(dnf downgrade --nogpgcheck -y --allowerasing --disablerepo '*')
    upgrade=(dnf -y upgrade --nogpgcheck --disablerepo '*')
elif command -v apt-get >/dev/null; then
    package_extension=deb
    apt_sources=/run/TEST-88-UPGRADE.sources
    apt_source_parts=/run/TEST-88-UPGRADE.sources.d
    : >"$apt_sources"
    mkdir -p "$apt_source_parts"
    apt_options=(
        -o "Dir::Etc::sourcelist=$apt_sources"
        -o "Dir::Etc::sourceparts=$apt_source_parts"
        --no-install-recommends
    )
    downgrade=(apt-get "${apt_options[@]}" install --allow-downgrades -y)
    upgrade=(apt-get "${apt_options[@]}" install -y)
else
    echo 'No supported package manager found, skipping test.' >/skipped
    exit 77
fi

minor=$(systemctl --version | awk '/^systemd/{print$2}')
networkd=
resolved=
udev=
unitscmd='systemctl list-units --failed *systemd*'

if command -v udevadm >/dev/null && systemctl is-active --quiet systemd-udevd.service; then
    udev=1
fi

: >/tmp/failed-units
if [[ $($unitscmd --output json | jq length) -gt 0 ]]; then
    echo 'Systemd failed units found before the test:'
    $unitscmd
    $unitscmd --output json | jq -r '.[].unit' >/tmp/failed-units
fi

save_unit_state() {
    local unit_files=/tmp/unit-files-before-package-operation.json
    local units=/tmp/units-before-package-operation.json

    rm -f /tmp/active-units /tmp/preexisting-units "$unit_files" "$units"
    if ! systemctl list-units --all '*systemd*' --output json >"$units" ||
        ! systemctl list-unit-files '*systemd*' --output json >"$unit_files" ||
        ! jq -r '.[].unit' "$units" >/tmp/preexisting-units ||
        ! jq -r '.[].unit_file' "$unit_files" >>/tmp/preexisting-units ||
        ! jq -r '
            .[]
            | select(.active == "active" or .active == "activating" or .active == "reloading")
            | .unit
        ' "$units" >/tmp/active-units; then
        echo 'Failed to save unit state before package operation, unit retries will be skipped.'
        rm -f /tmp/active-units /tmp/preexisting-units "$unit_files" "$units"
        return 0
    fi

    rm -f "$unit_files" "$units"
}

check_sd() {
    local load_state unit fail=0 timer1_new timer2_new

    if ! systemctl daemon-reload; then
        echo 'System manager reload failed after the test!'
        fail=1
    fi

    # Retry previously running and newly introduced units that failed while
    # package files were being replaced.
    if [[ -e /tmp/active-units && -e /tmp/preexisting-units ]]; then
        for unit in $($unitscmd --output json | jq -r '.[].unit'); do
            if grep -sxqF "$unit" /tmp/failed-units; then
                continue
            fi

            if ! grep -sxqF "$unit" /tmp/active-units && grep -sxqF "$unit" /tmp/preexisting-units; then
                continue
            fi

            if ! load_state=$(systemctl show -P LoadState "$unit"); then
                fail=1
                continue
            fi

            if ! systemctl reset-failed "$unit"; then
                if [[ $load_state != not-found ]]; then
                    fail=1
                fi
                continue
            fi

            if [[ $load_state != not-found ]] && ! systemctl start "$unit"; then
                fail=1
                systemctl status "$unit" || true
            fi
        done
    fi

    if ! systemd-run --quiet --wait --collect --service-type=exec true; then
        echo 'Transient service failed after the test!'
        fail=1
    fi

    if [[ -n $udev ]] && ! udevadm control --ping --timeout=5; then
        echo 'Udev failed after the test!'
        fail=1
    fi

    for unit in $($unitscmd --output json | jq -r '.[].unit'); do
        if grep -sxqF "$unit" /tmp/failed-units; then
            continue
        fi

        if [[ $(systemctl show -P LoadState "$unit") == not-found ]]; then
            continue
        fi

        fail=1
        systemctl status "$unit" || true
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

    if [[ -n $resolved ]]; then
        if ! resolvectl status; then
            echo 'Resolved failed after the test!'
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

save_unit_state
"${downgrade[@]}" "$pkgdir"/distro/*."$package_extension"

# Some distros don't ship networkd or resolved, so only test them when available
if command -v networkctl >/dev/null; then
    networkd=1
fi
if command -v resolvectl >/dev/null && systemctl is-active --quiet systemd-resolved.service; then
    resolved=1
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
save_unit_state
"${upgrade[@]}" "$pkgdir"/devel/*."$package_extension"

# TODO: sanity checks
check_sd

# Restore post.sh
mkdir -p /usr/lib/systemd/tests/testdata/units
mv /tmp/post.sh /usr/lib/systemd/tests/testdata/units/.

touch /testok
