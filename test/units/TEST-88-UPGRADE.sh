#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

pkgdir=/usr/host-pkgs

if ! [ -d "$pkgdir" ]; then
    echo "Distro packages not found in $pkgdir" >/skipped
    exit 77
fi

minor=$(systemctl --version |awk '/^systemd/{print$2}')
networkd=

check_sd() {
    if ! systemctl --failed |grep -Fqx '0 loaded units listed.'; then
        echo "Systemd failed units:"
        systemctl --failed
        exit 1
    fi
    [ -n "$networkd" ] && networkctl status
    loginctl list-sessions
    systemctl status TEST-88-UPGRADE.service
}

if dnf --version |grep -q '^4\.'; then
    disable='--disablerepo'
elif dnf --version |grep -q '^dnf5\s'; then
    disable='--disable-repo'
else
    echo 'Unknown dnf version!'
    exit 1
fi

# Copy the unit in /run so systemd finds it after the downgrade
cp /usr/lib/systemd/tests/testdata/units/TEST-88-UPGRADE.service /run/systemd/system

# FIXME: temporary hack to avoid this:
# file /usr/bin/systemd-sysusers from install of systemd-257-9.el10.x86_64 conflicts
# with file from package systemd-sysusers-258~devel-20250422134211.el10.x86_64
# This will be fixed in https://src.fedoraproject.org/rpms/systemd/pull-request/204
rpm -e --nodeps systemd-sysusers

dnf downgrade -y --allowerasing "$disable" '*' "$pkgdir"/distro/*.rpm

# Some distros doesn't ship networkd, so the test will always fail
if which networkctl >/dev/null; then
    networkd=1
fi

newminor=$(systemctl --version |awk '/^systemd/{print$2}')

if [ "$newminor" -lt "$minor" ]; then
    echo "Downgrade to $newminor was successful."
else
    echo "Downgrade failed. Current version is still $newminor."
    exit 1
fi

# TODO: sanity checks

check_sd

# Finally test the upgrade
dnf -y upgrade "$disable" '*' "$pkgdir"/devel/*.rpm

# TODO: sanity checks
check_sd
