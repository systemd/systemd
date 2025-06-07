#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/test-control.sh
. "$(dirname "$0")"/test-control.sh
# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

if ! command -v /usr/lib/systemd/systemd-keyutil >/dev/null; then
    echo "systemd-keyutil not found, skipping."
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
        -keyout /tmp/test.key -out /tmp/test.crt

testcase_validate() {
    /usr/lib/systemd/systemd-keyutil validate --certificate /tmp/test.crt --private-key /tmp/test.key
}

testcase_public() {
    PUBLIC="$(/usr/lib/systemd/systemd-keyutil public --certificate /tmp/test.crt)"
    assert_eq "$PUBLIC" "$(openssl x509 -in /tmp/test.crt -pubkey -noout)"

    PUBLIC="$(/usr/lib/systemd/systemd-keyutil public --private-key /tmp/test.key)"
    assert_eq "$PUBLIC" "$(openssl x509 -in /tmp/test.crt -pubkey -noout)"

    (! /usr/lib/systemd/systemd-keyutil public)
}

testcase_pkcs7() {
    echo -n "test" > /tmp/payload

    # Generate PKCS#1 signature
    openssl dgst -sha256 -sign /tmp/test.key -out /tmp/payload.sig /tmp/payload

    # Generate PKCS#7 "detached" signature
    /usr/lib/systemd/systemd-keyutil --certificate /tmp/test.crt --output /tmp/payload.p7s --signature /tmp/payload.sig pkcs7

    # Verify using internal x509 certificate
    openssl smime -verify -binary -inform der -in /tmp/payload.p7s -content /tmp/payload -noverify > /dev/null

    # Verify using external (original) x509 certificate
    openssl smime -verify -binary -inform der -in /tmp/payload.p7s -content /tmp/payload -certificate /tmp/test.crt -nointern -noverify > /dev/null

    rm -f /tmp/payload.p7s

    # Generate PKCS#7 non-"detached" signature
    /usr/lib/systemd/systemd-keyutil --certificate /tmp/test.crt --output /tmp/payload.p7s --signature /tmp/payload.sig --content /tmp/payload pkcs7

    # Verify using internal x509 certificate
    openssl smime -verify -binary -inform der -in /tmp/payload.p7s -noverify > /dev/null

    # Verify using external (original) x509 certificate
    openssl smime -verify -binary -inform der -in /tmp/payload.p7s -certificate /tmp/test.crt -nointern -noverify > /dev/null
}

run_testcases
