#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

bootctl

CURRENT_UKI=$(bootctl --print-stub-path)

echo "CURRENT UKI ($CURRENT_UKI):"
ukify inspect "$CURRENT_UKI"
if test -f /run/systemd/stub/profile; then
    echo "CURRENT PROFILE:"
    cat /run/systemd/stub/profile
fi
echo "CURRENT MEASUREMENT:"
/usr/lib/systemd/systemd-measure --current
if test -f /run/systemd/tpm2-pcr-signature.json; then
    echo "CURRENT SIGNATURE:"
    jq </run/systemd/tpm2-pcr-signature.json
fi

echo "CURRENT EVENT LOG + PCRS:"
/usr/lib/systemd/systemd-pcrlock

test -f /run/systemd/stub/profile

# shellcheck source=/dev/null
. /run/systemd/stub/profile

if [[ "$ID" == "main" ]]; then
    if [[ -f /root/encrypted.raw ]]; then
        exit 1
    fi

    # Prepare a disk image, locked to the PCR measurements of the current UKI
    truncate -s 32M /root/encrypted.raw
    echo -n "geheim" >/root/encrypted.secret
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom /root/encrypted.raw --key-file=/root/encrypted.secret
    systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs= --unlock-key-file=/root/encrypted.secret /root/encrypted.raw
    rm -f /root/encrypted.secret
fi

# Validate that with the current profile we can fulfill the PCR 11 policy
systemd-cryptsetup attach multiprof /root/encrypted.raw - tpm2-device=auto,headless=1
systemd-cryptsetup detach multiprof

if [[ "$ID" == "main" ]]; then
    bootctl set-default "$(basename "$CURRENT_UKI")@profile1"
    reboot
    exit 0
elif [[ "$ID" == "profile1" ]]; then
    grep testprofile1=1 /proc/cmdline
    bootctl set-default "$(basename "$CURRENT_UKI")@profile2"
    reboot
    exit 0
elif [[ "$ID" == "profile2" ]]; then
    grep testprofile2=1 /proc/cmdline
    rm /root/encrypted.raw
else
    exit 1
fi

touch /testok
