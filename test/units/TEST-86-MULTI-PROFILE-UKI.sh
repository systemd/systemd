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

if test ! -f /run/systemd/stub/profile; then
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out /root/pcrsign.private.pem
    openssl rsa -pubout -in /root/pcrsign.private.pem -out /root/pcrsign.public.pem

    ukify build --extend="$CURRENT_UKI" --output=/tmp/extended0.efi --profile='ID=profile0
TITLE="Profile Zero"' --measure-base="$CURRENT_UKI" --pcr-private-key=/root/pcrsign.private.pem --pcr-public-key=/root/pcrsign.public.pem --pcr-banks=sha256,sha384,sha512

    ukify build --extend=/tmp/extended0.efi --output=/tmp/extended1.efi --profile='ID=profile1
TITLE="Profile One"' --measure-base=/tmp/extended0.efi --cmdline="testprofile1=1 $(cat /proc/cmdline)" --pcr-private-key=/root/pcrsign.private.pem --pcr-public-key=/root/pcrsign.public.pem --pcr-banks=sha256,sha384,sha512

    ukify build --extend=/tmp/extended1.efi --output=/tmp/extended2.efi --profile='ID=profile2
TITLE="Profile Two"' --measure-base=/tmp/extended1.efi --cmdline="testprofile2=1 $(cat /proc/cmdline)" --pcr-private-key=/root/pcrsign.private.pem --pcr-public-key=/root/pcrsign.public.pem --pcr-banks=sha256,sha384,sha512

    echo "EXTENDED UKI:"
    ukify inspect /tmp/extended2.efi
    rm /tmp/extended0.efi /tmp/extended1.efi
    mv /tmp/extended2.efi "$CURRENT_UKI"

    # Prepare a disk image, locked to the PCR measurements of the UKI we just generated
    truncate -s 32M /root/encrypted.raw
    echo -n "geheim" >/root/encrypted.secret
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom /root/encrypted.raw --key-file=/root/encrypted.secret
    systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs= --tpm2-public-key=/root/pcrsign.public.pem --unlock-key-file=/root/encrypted.secret /root/encrypted.raw
    rm -f /root/encrypted.secret

    reboot
    exit 0
else
    # shellcheck source=/dev/null
    . /run/systemd/stub/profile

    # Validate that with the current profile we can fulfill the PCR 11 policy
    systemd-cryptsetup attach multiprof /root/encrypted.raw - tpm2-device=auto,headless=1
    systemd-cryptsetup detach multiprof

    if [ "$ID" = "profile0" ]; then
        grep -v testprofile /proc/cmdline
        echo "default $(basename "$CURRENT_UKI")@profile1" >"$(bootctl -p)/loader/loader.conf"
        reboot
        exit 0
    elif [ "$ID" = "profile1" ]; then
        grep testprofile1=1 /proc/cmdline
        echo "default $(basename "$CURRENT_UKI")@profile2" >"$(bootctl -p)/loader/loader.conf"
        reboot
        exit 0
    elif [ "$ID" = "profile2" ]; then
        grep testprofile2=1 /proc/cmdline
        rm /root/encrypted.raw
    else
        exit 1
    fi
fi

touch /testok
