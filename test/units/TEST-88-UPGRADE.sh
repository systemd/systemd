#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

if ! [ -d /usr/host-pkgs ]; then
    touch /skipped
    exit 0
fi

minor=$(systemctl --version |awk '/^systemd/{print$2}')

dnf install -y --allowerasing --disablerepo='*' /usr/host-pkgs/*.rpm

newminor=$(systemctl --version |awk '/^systemd/{print$2}')

if [ "$newminor" -eq "$minor" ]; then
    echo "Downgrade to $newminor was successful."
else
    echo "Downgrade failed. Current version is still $newminor."
    exit 1
fi

# TODO: sanity checks

systemctl --failed |grep -Fqx '0 loaded units listed.'
networkctl status
loginctl list-sessions

if dnf -y upgrade systemd; then
    echo 'Upgrade failed.'
    exit 1
fi

# TODO: sanity checks

systemctl --failed |grep -Fqx '0 loaded units listed.'
networkctl status
loginctl list-sessions
