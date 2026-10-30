#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

if ! systemd-analyze has-tpm2; then
    echo "Full TPM2 support not available, skipping the test"
    exit 0
fi

bootctl

STUB_PATH=$(bootctl --print-stub-path)
CURRENT_UKI=$STUB_PATH
# With boot counting, systemd-bless-boot may already have renamed the UKI.
if [[ ! -f "$CURRENT_UKI" ]]; then
    CURRENT_UKI="${CURRENT_UKI%+*}.efi"
fi
MEASURE=/usr/lib/systemd/systemd-measure

echo "CURRENT UKI ($CURRENT_UKI):"
ukify inspect "$CURRENT_UKI"
if test -f /run/systemd/stub/profile; then
    echo "CURRENT PROFILE:"
    cat /run/systemd/stub/profile
fi

# systemd-measure is optional
if [ -x "$MEASURE" ]; then
    echo "CURRENT MEASUREMENT:"
    "$MEASURE" --current
fi
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
    # Give the UKI a mixed case name with a boot counter. Entry IDs are matched case insensitively
    # and without the counter, so the lower case ID without counter has to keep working.
    mv "$CURRENT_UKI" "$(dirname "$CURRENT_UKI")/Multi-Profile+3.efi"
    bootctl set-default "multi-profile.efi@profile1"
    reboot
    exit 0
elif [[ "$ID" == "profile1" ]]; then
    grep testprofile1=1 /proc/cmdline
    # The renamed UKI with the boot counter has to be what systemd-boot booted.
    [[ "$(basename "$STUB_PATH")" == Multi-Profile+* ]]
    # The profile ID is "Profile2", the lower case entry ID has to match it anyway.
    bootctl set-default "multi-profile.efi@profile2"
    reboot
    exit 0
elif [[ "$ID" == "Profile2" ]]; then
    grep testprofile2=1 /proc/cmdline
    rm /root/encrypted.raw
    # Reset the default boot entry so a subsequent re-run of the test does not
    # boot straight back into @profile2 (where encrypted.raw is now gone) and fail.
    bootctl set-default ""
else
    exit 1
fi

touch /testok
