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
    local snapshot_failed="" trigger_list unit
    local unit_files=/tmp/unit-files-before-package-operation.json
    local units=/tmp/units-before-package-operation.json
    local -a state_files=(/tmp/active-units /tmp/preexisting-units /tmp/triggered-units)
    local -a triggers

    rm -f "${state_files[@]}" "$unit_files" "$units"
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
        snapshot_failed=1
    fi

    if [[ -z $snapshot_failed ]]; then
        : >/tmp/triggered-units
        while read -r unit; do
            if ! trigger_list=$(systemctl show -P Triggers "$unit"); then
                echo 'Failed to save unit triggers before package operation, unit retries will be skipped.'
                snapshot_failed=1
                break
            fi

            if [[ -n $trigger_list ]]; then
                read -ra triggers <<<"$trigger_list"
                printf '%s\n' "${triggers[@]}" >>/tmp/triggered-units
            fi
        done </tmp/active-units
    fi

    rm -f "$unit_files" "$units"

    if [[ -n $snapshot_failed ]]; then
        rm -f "${state_files[@]}"
    fi
}

save_package_units() {
    local package_set=$1 package packages_found=
    local paths="/tmp/$package_set-package-paths"
    local units="/tmp/$package_set-units"

    rm -f "$paths" "$units"
    for package in "$pkgdir/$package_set"/*."$package_extension"; do
        [[ -e $package ]] || continue
        packages_found=1

        if [[ $package_extension == deb ]]; then
            if ! dpkg-deb --fsys-tarfile "$package" | tar -tf - >>"$paths"; then
                echo "Failed to inspect $package_set packages, removed units will be treated as failures."
                rm -f "$paths"
                return 0
            fi
        elif ! rpm -qlp "$package" >>"$paths"; then
            echo "Failed to inspect $package_set packages, removed units will be treated as failures."
            rm -f "$paths"
            return 0
        fi
    done

    if [[ -z $packages_found ]]; then
        echo "No $package_set packages found, removed units will be treated as failures."
        return 0
    fi

    sed -n -E 's#^(\./|/)?(usr/)?lib/systemd/system/([^/]+)$#\3#p' "$paths" |
        sort -u >"$units"
    rm -f "$paths"
}

unit_removal_expected() {
    local operation=$1 unit=$2
    local template units

    if [[ $operation == downgrade ]]; then
        units=/tmp/distro-units
    else
        units=/tmp/devel-units
    fi

    [[ -s $units ]] || return 1
    grep -sxqF "$unit" "$units" && return 1

    if [[ $unit == *@*.* ]]; then
        template="${unit%%@*}@.${unit##*.}"
        grep -sxqF "$template" "$units" && return 1
    fi

    return 0
}

check_sd() {
    local operation=$1 load_state unit fail=0 timer1_new timer2_new

    if ! systemctl daemon-reload; then
        echo 'System manager reload failed after the test!'
        fail=1
    fi

    # Reset units activated during package replacement, then restart only units
    # that were previously running or are newly introduced.
    rm -f /tmp/restart-units /tmp/retry-units
    if [[ -e /tmp/active-units && -e /tmp/preexisting-units && -e /tmp/triggered-units ]]; then
        : >/tmp/restart-units
        : >/tmp/retry-units
        for unit in $($unitscmd --output json | jq -r '.[].unit'); do
            if grep -sxqF "$unit" /tmp/failed-units; then
                continue
            fi

            if ! grep -sxqF "$unit" /tmp/active-units &&
                ! grep -sxqF "$unit" /tmp/triggered-units &&
                grep -sxqF "$unit" /tmp/preexisting-units; then
                continue
            fi

            if ! load_state=$(systemctl show -P LoadState "$unit"); then
                fail=1
                continue
            fi

            if [[ $load_state == not-found ]]; then
                if unit_removal_expected "$operation" "$unit"; then
                    systemctl reset-failed "$unit" || true
                else
                    fail=1
                    systemctl status "$unit" || true
                fi
                continue
            fi

            if ! systemctl reset-failed "$unit"; then
                fail=1
                continue
            fi

            if grep -sxqF "$unit" /tmp/active-units || ! grep -sxqF "$unit" /tmp/preexisting-units; then
                echo "$unit" >>/tmp/restart-units
            else
                echo "$unit" >>/tmp/retry-units
            fi
        done

        while read -r unit; do
            if ! systemctl start "$unit"; then
                fail=1
                systemctl status "$unit" || true
            fi
        done </tmp/restart-units

        while read -r unit; do
            if ! systemctl start "$unit"; then
                fail=1
                systemctl status "$unit" || true
            elif ! systemctl stop "$unit"; then
                fail=1
                systemctl status "$unit" || true
            fi
        done </tmp/retry-units
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

        if ! load_state=$(systemctl show -P LoadState "$unit"); then
            fail=1
            continue
        fi

        if [[ $load_state == not-found ]] && unit_removal_expected "$operation" "$unit"; then
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
save_package_units distro
save_package_units devel
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

check_sd downgrade

# Finally test the upgrade
save_unit_state
"${upgrade[@]}" "$pkgdir"/devel/*."$package_extension"

# TODO: sanity checks
check_sd upgrade

# Restore post.sh
mkdir -p /usr/lib/systemd/tests/testdata/units
mv /tmp/post.sh /usr/lib/systemd/tests/testdata/units/.

touch /testok
