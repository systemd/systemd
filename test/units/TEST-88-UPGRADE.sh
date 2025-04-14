#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# -*- mode: shell-script; indent-tabs-mode: nil; sh-basic-offset: 4; -*-
# ex: ts=8 sw=4 sts=4 et filetype=sh
set -eux
set -o pipefail

minor=$(systemctl --version |awk '/^systemd/{print$2}')
previous=$((minor-1))

# TODO: support other package managers other than dnf
previous_minor=$(dnf --showduplicates info systemd |awk '$1 == "Version" && $3 ~ /^256/ {print$3}' |sort -unr)

for $ver in $previous_minor; do
    if dnf -y install "systemd-$ver"; then
        downgraded=$ver
        break
    fi
done

if [ -z "$downgraded" ]; then
    echo 'No previous version of systemd found.'
    exit 1
fi

newminor=$(systemctl --version |awk '/^systemd/{print$2}')
if [ "$newminor" -eq "$previous" ]; then
    echo "Downgrade to $downgraded was successful."
else
    echo "Downgrade failed. Current version is still $newminor."
    exit 1
fi

# TODO: sanity checks

if dnf -y upgrade systemd; then
    echo 'Upgrade failed.'
    exit 1
fi

# TODO: sanity checks
