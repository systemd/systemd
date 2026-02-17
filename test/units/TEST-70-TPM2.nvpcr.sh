#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
SD_PCREXTEND="/usr/lib/systemd/systemd-pcrextend"

if [[ ! -x "${SD_PCREXTEND:?}" ]] || ! tpm_has_pcr sha256 11; then
    echo "$SD_PCREXTEND or PCR sysfs files not found, skipping PCR extension tests"
    exit 0
fi

at_exit() {
    if [[ $? -ne 0 ]]; then
        # Dump the event log on fail, to make debugging a bit easier
        jq --seq --slurp </run/log/systemd/tpm2-measure.log
    fi

    rm -rf /run/nvpcr /tmp/nvpcr
    rm -f /var/tmp/nvpcr.raw /run/verity.d/test-79-nvpcr.crt
}

trap at_exit EXIT

# Temporarily override sd-pcrextend's sanity checks
export SYSTEMD_FORCE_MEASURE=1

mkdir -p /run/nvpcr

cat >/run/nvpcr/test.nvpcr <<EOF
{"name":"test","algorithm":"sha256","nvIndex":30474762}
EOF
/usr/lib/systemd/systemd-tpm2-setup
test -f /run/systemd/nvpcr/test.anchor
/usr/lib/systemd/systemd-pcrextend --nvpcr=test schrumpel
# To calculate the current value we need the anchor measurement
DIGEST_BASE="$(cat /run/systemd/nvpcr/test.anchor)"
DIGEST_MEASURED="$(echo -n "schrumpel" | openssl dgst -sha256 -hex -r | cut -d' ' -f1)"
DIGEST_EXPECTED="$(echo "$DIGEST_BASE$DIGEST_MEASURED" | tr '[:lower:]' '[:upper:]' | basenc --base16 -d | openssl dgst -sha256 -hex -r | cut -d' ' -f1)"
DIGEST_ACTUAL="$(systemd-analyze nvpcrs test --json=pretty | jq -r '.[] | select(.name=="test") | .value')"
test "$DIGEST_ACTUAL" = "$DIGEST_EXPECTED"

# Now "destroy" the value via another measurement (this time we use Varlink, to test the API)
varlinkctl call /usr/lib/systemd/systemd-pcrextend io.systemd.PCRExtend.Extend '{"nvpcr":"test","text":"schnurz"}'
DIGEST_ACTUAL2="$(systemd-analyze nvpcrs test --json=pretty | jq -r '.[] | select(.name=="test") | .value')"
test "$DIGEST_ACTUAL2" != "$DIGEST_EXPECTED"

# And calculate the new result
DIGEST_MEASURED2="$(echo -n "schnurz" | openssl dgst -sha256 -hex -r | cut -d' ' -f1)"
DIGEST_EXPECTED2="$(echo "$DIGEST_EXPECTED$DIGEST_MEASURED2" | tr '[:lower:]' '[:upper:]' | basenc --base16 -d | openssl dgst -sha256 -hex -r | cut -d' ' -f1)"
test "$DIGEST_ACTUAL2" = "$DIGEST_EXPECTED2"

mkdir /tmp/nvpcr

OPENSSL_CONFIG="/tmp/nvpcr/opensslconfig"
# Unfortunately OpenSSL insists on reading some config file, hence provide one with mostly placeholder contents
cat >"${OPENSSL_CONFIG:?}" <<EOF
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

openssl req -config "$OPENSSL_CONFIG" -subj="/CN=waldo" \
            -x509 -sha256 -nodes -days 365 -newkey rsa:4096 \
            -keyout /tmp/nvpcr/test-70-nvpcr.key -out /tmp/nvpcr/test-70-nvpcr.crt

mkdir /tmp/nvpcr/tree
touch /tmp/nvpcr/tree/file

SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
    systemd-repart -P \
                   -s /tmp/nvpcr/tree \
                   --certificate=/tmp/nvpcr/test-70-nvpcr.crt \
                   --private-key=/tmp/nvpcr/test-70-nvpcr.key \
                   /var/tmp/nvpcr.raw

mkdir -p /run/verity.d
cp /tmp/nvpcr/test-70-nvpcr.crt /run/verity.d/

cp /run/log/systemd/tpm2-measure.log /tmp/nvpcr/log-before

systemd-dissect --image-policy='root=signed:=absent+unused' --mtree /var/tmp/nvpcr.raw

set +o pipefail
diff /tmp/nvpcr/log-before /run/log/systemd/tpm2-measure.log | grep -F '"content":{"nvIndexName":"verity","string":"verity:'
