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

verify_pkcs7() {
    # Verify using internal certificate
    openssl smime -verify -binary -inform der -in /tmp/payload.p7s -content /tmp/payload -noverify > /dev/null
    # Verify using external (original) certificate
    openssl smime -verify -binary -inform der -in /tmp/payload.p7s -content /tmp/payload -noverify -certfile /tmp/test.crt -nointern > /dev/null
}

verify_pkcs7_fail() {
    # Verify using internal certificate
    (! openssl smime -verify -binary -inform der -in /tmp/payload.p7s -content /tmp/payload -noverify > /dev/null)
    # Verify using external (original) certificate
    (! openssl smime -verify -binary -inform der -in /tmp/payload.p7s -content /tmp/payload -noverify -certfile /tmp/test.crt -nointern > /dev/null)
}

testcase_pkcs7() {
    echo -n "test" > /tmp/payload

    for hashalg in sha256 sha384 sha512; do
        # shellcheck disable=SC2086
        openssl dgst -$hashalg -sign /tmp/test.key -out /tmp/payload.p1s /tmp/payload

        # Test with and without content in the PKCS7
        for content_param in "" "--content /tmp/payload"; do
            # Test with and without specifying signing hash alg
            for hashalg_param in "" "--hash-algorithm $hashalg"; do
                # shellcheck disable=SC2086
                /usr/lib/systemd/systemd-keyutil --certificate /tmp/test.crt --output /tmp/payload.p7s --signature /tmp/payload.p1s $content_param $hashalg_param pkcs7

                # Should always pass, except when not specifying hash alg and hash alg != sha256
                if [ -z "$hashalg_param" ] && [ "$hashalg" != "sha256" ]; then
                    verify_pkcs7_fail
                else
                    verify_pkcs7
                fi

                rm -f /tmp/payload.p7s
            done
        done

        rm -f /tmp/payload.p1s
    done

    rm -f /tmp/payload
}

run_testcases
