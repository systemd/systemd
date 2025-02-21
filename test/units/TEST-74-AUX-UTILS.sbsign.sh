#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh

if ! command -v /usr/lib/systemd/systemd-sbsign >/dev/null; then
    echo "systemd-sbsign not found, skipping."
    exit 0
fi

if [[ ! -d /usr/lib/systemd/boot/efi ]]; then
    echo "systemd-boot is not installed, skipping."
    exit 0
fi

cat >/tmp/openssl.conf <<EOF
[ req ]
prompt = no
distinguished_name = req_distinguished_name

[ req_distinguished_name ]
C = DE
ST = Test State
L = Test Locality
O = Org Name
OU = Org Unit Name
CN = Common Name
emailAddress = test@email.com
EOF

openssl req -config /tmp/openssl.conf -subj="/CN=waldo" \
        -x509 -sha256 -nodes -days 365 -newkey rsa:4096 \
        -keyout /tmp/sb.key -out /tmp/sb.crt

testcase_sign_systemd_boot() {
    if ! command -v sbverify >/dev/null; then
        echo "sbverify not found, skipping."
        return 0
    fi

    SD_BOOT="$(find /usr/lib/systemd/boot/efi/ -name "systemd-boot*.efi" | head -n1)"

    (! sbverify --cert /tmp/sb.crt "$SD_BOOT")
    /usr/lib/systemd/systemd-sbsign sign --certificate /tmp/sb.crt --private-key /tmp/sb.key --output /tmp/sdboot "$SD_BOOT"
    sbverify --cert /tmp/sb.crt /tmp/sdboot

    # Make sure appending signatures to an existing certificate table works as well.
    /usr/lib/systemd/systemd-sbsign sign --certificate /tmp/sb.crt --private-key /tmp/sb.key --output /tmp/sdboot /tmp/sdboot
    sbverify --cert /tmp/sb.crt /tmp/sdboot
}

testcase_sign_systemd_boot_offline() {
    if ! command -v sbverify >/dev/null; then
        echo "sbverify not found, skipping."
        return 0
    fi

    SD_BOOT="$(find /usr/lib/systemd/boot/efi/ -name "systemd-boot*.efi" | head -n1)"

    /usr/lib/systemd/systemd-sbsign export-signed-attributes --certificate /tmp/sb.crt --output /tmp/sattrs.bin "$SD_BOOT"
    openssl dgst -sha256 -sign /tmp/sb.key -out /tmp/sattrs.sig /tmp/sattrs.bin
    /usr/lib/systemd/systemd-sbsign \
        sign \
        --certificate /tmp/sb.crt \
        --output /tmp/sdboot \
        --signed-attributes /tmp/sattrs.bin \
        --signed-attributes-signature /tmp/sattrs.sig \
        "$SD_BOOT"

    sbverify --cert /tmp/sb.crt /tmp/sdboot
}

run_testcases
