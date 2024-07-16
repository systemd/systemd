#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# FIXME: test that kernel cmdline reached us properly
# FIXME: make sure systemd-measure worked

bootctl

CURRENT_UKI=$(bootctl --print-stub-path)

echo "CURRENT UKI ($CURRENT_UKI):"
ukify inspect "$CURRENT_UKI"

if test ! -f /run/systemd/stub/profile; then
    ukify build --extend="$CURRENT_UKI" --output=/tmp/extended0.efi --profile='ID=profile0
TITLE="Profile Zero"'

    ukify build --extend=/tmp/extended0.efi --output=/tmp/extended1.efi --profile='ID=profile1
TITLE="Profile One"' --cmdline="$(cat /proc/cmdline) testprofile1=1"

    ukify build --extend=/tmp/extended1.efi --output=/tmp/extended2.efi --profile='ID=profile2
TITLE="Profile Two"' --cmdline="$(cat /proc/cmdline) testprofile2=1"

    echo "EXTENDED UKI:"
    ukify inspect /tmp/extended2.efi

    mv /tmp/extended2.efi "$CURRENT_UKI"
    reboot
    exit 0
else
    source /run/systemd/stub/profile

    if [ "$ID" = "profile0" ]; then
        echo "default $(basename "$CURRENT_UKI")@profile1" > "$(bootctl -p)/loader/loader.conf"
        reboot
        exit 0
    elif [ "$ID" = "profile1" ]; then
        echo "default $(basename "$CURRENT_UKI")@profile2" > "$(bootctl -p)/loader/loader.conf"
        reboot
        exit 0
    elif [ "$ID" != "profile2" ]; then
        exit 1
    fi
fi

touch /testok
