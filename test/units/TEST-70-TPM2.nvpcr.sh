#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
SD_PCREXTEND="/usr/lib/systemd/systemd-pcrextend"
SD_TPM2SETUP="/usr/lib/systemd/systemd-tpm2-setup"
SD_MEASURE="/usr/lib/systemd/systemd-measure"

if [[ ! -x "${SD_PCREXTEND:?}" ]] || [[ ! -x "${SD_MEASURE:?}" ]] || ! tpm_has_pcr sha256 11; then
    echo "$SD_PCREXTEND, $SD_MEASURE or PCR sysfs files not found, skipping PCR extension tests"
    exit 0
fi

at_exit() {
    if [[ $? -ne 0 ]]; then
        # Dump the event log on fail, to make debugging a bit easier
        jq --seq --slurp </run/log/systemd/tpm2-measure.log
    fi

    mv -f /run/systemd/tpm2-pcr-public-key.pem.bak /run/systemd/tpm2-pcr-public-key.pem
    mv -f /run/systemd/tpm2-pcr-signature.json.bak /run/systemd/tpm2-pcr-signature.json
    rm -f /tmp/tpm2-pcr-private-key.pem
    rm -rf /run/nvpcr /tmp/nvpcr
    rm -f /var/tmp/nvpcr.raw /run/verity.d/test-70-nvpcr.crt
    rm -f /run/systemd/nvpcr/test.auth /run/systemd/nvpcr/test2.auth /run/systemd/nvpcr/aaa.auth /run/systemd/nvpcr/zzz.auth
    rm -r /tmp/test.policy
}

trap at_exit EXIT

# systemd-tpm2-setup returns EX_UNAVAILABLE rather than 0 when it cannot set something up but this
# is still considered success. This happens at the moment because there is no EK certificate in
# QEMU guests.
run_tpm2_setup() {
    local rc=0
    "$SD_TPM2SETUP" || rc=$?
    [[ "$rc" -eq 0 || "$rc" -eq 69 ]]
}

# Temporarily override sd-pcrextend's sanity checks
export SYSTEMD_FORCE_MEASURE=1

# Temporarily override the PCR signing key and PCR signatures to create a signed
# PCR policy that's valid for the current state
mv /run/systemd/tpm2-pcr-public-key.pem /run/systemd/tpm2-pcr-public-key.pem.bak
# XXX: This gets removed in TEST-70-TPM2.measure.sh, but the intention here is to preserve the original one.
touch /run/systemd/tpm2-pcr-signature.json
mv /run/systemd/tpm2-pcr-signature.json /run/systemd/tpm2-pcr-signature.json.bak
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "/tmp/tpm2-pcr-private-key.pem"
openssl rsa -pubout -in "/tmp/tpm2-pcr-private-key.pem" -out "/run/systemd/tpm2-pcr-public-key.pem"
"$SD_MEASURE" sign --current --bank sha256 --private-key="/tmp/tpm2-pcr-private-key.pem" --public-key="/run/systemd/tpm2-pcr-public-key.pem" --phase=":" --policyref="nvpcr-init" >"/run/systemd/tpm2-pcr-signature.json"

mkdir -p /run/nvpcr

cat >/run/nvpcr/test.nvpcr <<EOF
{"name":"test","algorithm":"sha256","nvIndex":30474762}
EOF
run_tpm2_setup
test -f /run/systemd/nvpcr/test.auth
# The initial measurement is all zeroes
DIGEST_BASE_UNINITIALIZED="0000000000000000000000000000000000000000000000000000000000000000"
DIGEST_INITIAL_MEASUREMENT="0000000000000000000000000000000000000000000000000000000000000000"
DIGEST_BASE_EXPECTED=$(echo "$DIGEST_BASE_UNINITIALIZED$DIGEST_INITIAL_MEASUREMENT" | tr '[:lower:]' '[:upper:]' | basenc --base16 -d | openssl dgst -sha256 -hex -r | cut -d' ' -f1)
DIGEST_BASE="$(systemd-analyze nvpcrs test --json=pretty | jq -r '.[] | select(.name=="test") | .value')"
test "$DIGEST_BASE" = "$DIGEST_BASE_EXPECTED"

ANCHOR_MEASUREMENT_STRING_EXPECTED="nvpcr-init:test:0x1d1020a:$(tpm2_nvreadpublic 0x01d1020a | awk '/name:/{print $2; exit}')"
ANCHOR_MEASUREMENT_STRING=$(jq --seq --slurp -r '[.[] | select(.content.eventType=="nvpcr-init") | .content.string] | last' </run/log/systemd/tpm2-measure.log)
test "$ANCHOR_MEASUREMENT_STRING" = "$ANCHOR_MEASUREMENT_STRING_EXPECTED"

"$SD_PCREXTEND" --nvpcr=test schrumpel
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

# Make sure that systemd-tpm2-setup recognizes the pre-existing NV index as valid, to simulate
# what we expect on a fresh boot.
POLICY=$(tpm2_nvreadpublic 0x01d1020a | awk '/authorization policy:/{print $3; exit}')
echo "$POLICY" | basenc --base16 -d >/tmp/test.policy
rm -f /run/systemd/nvpcr/test.auth
tpm2_nvundefine -C o 0x01d1020a
tpm2_nvdefine -C o -s 32 -g sha256 -a "policywrite|ownerread|authread|orderly|clear_stclear|nt=extend" -L /tmp/test.policy 0x01d1020a
run_tpm2_setup
test -f /run/systemd/nvpcr/test.auth
DIGEST_ACTUAL3="$(systemd-analyze nvpcrs test --json=pretty | jq -r '.[] | select(.name=="test") | .value')"
test "$DIGEST_ACTUAL3" = "$DIGEST_BASE_EXPECTED"

# Verify the 'priority' field round-trips through the JSON definition. The 'test' NvPCR above sets no
# priority, so it must report the default (1000).
PRIORITY_DEFAULT="$(systemd-analyze nvpcrs test --json=pretty | jq -r '.[] | select(.name=="test") | .priority')"
test "$PRIORITY_DEFAULT" = "1000"

# A definition with an explicit priority must report exactly that value.
cat >/run/nvpcr/test2.nvpcr <<EOF
{"name":"test2","algorithm":"sha256","nvIndex":30474763,"priority":42}
EOF
PRIORITY_EXPLICIT="$(systemd-analyze nvpcrs test2 --json=pretty | jq -r '.[] | select(.name=="test2") | .priority')"
test "$PRIORITY_EXPLICIT" = "42"

# Verify NvPCRs are allocated in order of priority (lower value = more important = allocated first),
# independent of lexical filename order. 'aaa' is lexically first but less important (higher priority
# value), while 'zzz' is lexically last but more important (lower priority value), so 'zzz' must be set
# up before 'aaa'.
cat >/run/nvpcr/aaa.nvpcr <<EOF
{"name":"aaa","algorithm":"sha256","nvIndex":30474772,"priority":900}
EOF
cat >/run/nvpcr/zzz.nvpcr <<EOF
{"name":"zzz","algorithm":"sha256","nvIndex":30474773,"priority":100}
EOF
SETUP_LOG="$(run_tpm2_setup 2>&1)"
AAA_LINE="$(echo "$SETUP_LOG" | grep -n "Setting up NvPCR 'aaa'" | cut -d: -f1)"
ZZZ_LINE="$(echo "$SETUP_LOG" | grep -n "Setting up NvPCR 'zzz'" | cut -d: -f1)"
test "$ZZZ_LINE" -lt "$AAA_LINE"

# Verify that we can't redefine an NvPCR once we've exitted early boot by extending PCR11.
rm -f /run/systemd/nvpcr/test.auth
tpm2_nvundefine -C o 0x01d1020a
"$SD_PCREXTEND" --pcr 11 "foo"
SETUP_LOG="$(rc=0; $SD_TPM2SETUP 2>&1 || rc=$?; [[ "$rc" -ne 0 ]] && [[ "$rc" -ne 69 ]])"
grep -F "Failed to initialize NvPCR index: Device not a stream" <<<"$SETUP_LOG" >/dev/null

# Test the --login= mode and the 'login' NvPCR, used in production by systemd-pcrlogin@.service.
if [[ -f /usr/lib/nvpcr/login.nvpcr ]]; then
    login_nvpcr_value() {
        systemd-analyze nvpcrs login --json=pretty | jq -r '.[] | select(.name=="login") | .value'
    }

    # Extract the most recently measured word for the 'login' NvPCR from the event log.
    login_last_word() {
        jq --seq --slurp -r '[.[] | select(.content.nvIndexName=="login") | .content.string] | last' </run/log/systemd/tpm2-measure.log
    }

    # Measure root's user record. This lazily initializes the 'login' NvPCR if it isn't already.
    "$SD_PCREXTEND" --login=root

    # The 'login' NvPCR must now exist and carry a non-empty value.
    LOGIN_DIGEST1="$(login_nvpcr_value)"
    test -n "$LOGIN_DIGEST1"
    test "$LOGIN_DIGEST1" != "null"

    # A matching event log entry must be present (the word is "login:<name>:<canonical json>").
    grep -F '"nvIndexName":"login","string":"login:root:' /run/log/systemd/tpm2-measure.log >/dev/null
    LOGIN_WORD_BY_NAME="$(login_last_word)"

    # Looking the same user up by numeric UID must yield the identical measured word
    # (systemd-pcrextend uses USERDB_PARSE_NUMERIC, and systemd-pcrlogin@.service is instanced by UID).
    "$SD_PCREXTEND" --login=0
    LOGIN_WORD_BY_UID="$(login_last_word)"
    test "$LOGIN_WORD_BY_NAME" = "$LOGIN_WORD_BY_UID"

    # Direct tool invocations always re-extend (the once-per-boot guarantee lives in the unit's
    # RemainAfterExit=yes, not in the tool), so the NvPCR value must have advanced.
    LOGIN_DIGEST2="$(login_nvpcr_value)"
    test "$LOGIN_DIGEST2" != "$LOGIN_DIGEST1"
fi

systemd-analyze identify-tpm2
udevadm test-builtin 'tpm2_id identify' /dev/tpmrm0

# systemd-dissect calls io.systemd.PCRExtend over Varlink to extend the verity NvPCR after activation,
# but systemd-pcrextend.socket has ConditionSecurity=measured-os which fails when the firmware did not
# initialize PCRs (e.g. when not booting via a signed UKI). Skip the rest in that case, otherwise the
# 'diff | grep' below would find no new measurement and fail.
if ! systemctl is-active --quiet systemd-pcrextend.socket; then
    echo "systemd-pcrextend.socket not active, skipping verity NvPCR measurement check"
    exit 0
fi

mkdir -p /tmp/nvpcr/tree
touch /tmp/nvpcr/tree/file

if machine_supports_verity_keyring; then
    SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
        systemd-repart -P \
                    -s /tmp/nvpcr/tree \
                    --certificate=/usr/share/mkosi.crt \
                    --private-key=/usr/share/mkosi.key \
                    /var/tmp/nvpcr.raw
else
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

    SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
        systemd-repart -P \
                    -s /tmp/nvpcr/tree \
                    --certificate=/tmp/nvpcr/test-70-nvpcr.crt \
                    --private-key=/tmp/nvpcr/test-70-nvpcr.key \
                    /var/tmp/nvpcr.raw

    mkdir -p /run/verity.d
    cp /tmp/nvpcr/test-70-nvpcr.crt /run/verity.d/
fi

cp /run/log/systemd/tpm2-measure.log /tmp/nvpcr/log-before

systemd-dissect --image-policy='root=signed:=absent+unused' --mtree /var/tmp/nvpcr.raw

set +o pipefail
diff /tmp/nvpcr/log-before /run/log/systemd/tpm2-measure.log | grep -F '"content":{"nvIndexName":"verity","string":"verity:'
