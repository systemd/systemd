#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# FIXME: make sure systemd-measure worked

bootctl

CURRENT_UKI=$(bootctl --print-stub-path)

echo "CURRENT UKI ($CURRENT_UKI):"
ukify inspect "$CURRENT_UKI"

if test ! -f /run/systemd/stub/profile; then
    ukify build --extend="$CURRENT_UKI" --output=/tmp/extended0.efi --profile='ID=profile0
TITLE="Profile Zero"'

    ukify build --extend=/tmp/extended0.efi --output=/tmp/extended1.efi --profile='ID=profile1
TITLE="Profile One"' --cmdline="testprofile1=1 $(cat /proc/cmdline)"

    ukify build --extend=/tmp/extended1.efi --output=/tmp/extended2.efi --profile='ID=profile2
TITLE="Profile Two"' --cmdline="testprofile2=1 $(cat /proc/cmdline)"

    echo "EXTENDED UKI:"
    ukify inspect /tmp/extended2.efi

    mv /tmp/extended2.efi "$CURRENT_UKI"
    reboot
    exit 0
else
    # shellcheck disable=SC1090
    . /run/systemd/stub/profile

    if [ "$ID" = "profile0" ]; then
        grep -v testprofile /proc/cmdline
        echo "default $(basename "$CURRENT_UKI")@profile1" > "$(bootctl -p)/loader/loader.conf"
        reboot
        exit 0
    elif [ "$ID" = "profile1" ]; then
        grep testprofile1=1 /proc/cmdline
        echo "default $(basename "$CURRENT_UKI")@profile2" > "$(bootctl -p)/loader/loader.conf"
        reboot
        exit 0
    elif [ "$ID" == "profile2" ]; then
        grep testprofile2=1 /proc/cmdline
    else
        exit 1
    fi
fi

touch /testok
