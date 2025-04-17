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
}

if dnf --version |grep -q '^4\.'; then
    enabl='--enablerepo'
    disable='--disablerepo'
elif dnf --version |grep -q '^dnf5\s'; then
    enabl='--enable-repo'
    disable='--disable-repo'
else
    echo 'Unknown dnf version!'
    exit 1
fi

# temporary hack until we merge https://src.fedoraproject.org/rpms/systemd/pull-request/204
rpm -e --nodeps systemd-sysusers

dnf downgrade -y --allowerasing "$disable" '*' "$enabl" oldpackages systemd

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
dnf upgrade -y --allowerasing "$disable" '*' "$enabl" newpackages systemd

# TODO: sanity checks
check_sd
