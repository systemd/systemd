#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
SD_PCREXTEND="/usr/lib/systemd/systemd-pcrextend"

if [[ ! -x "${SD_PCREXTEND:?}" ]] || ! tpm_has_pcr sha256 11 || ! tpm_has_pcr sha256 15; then
    echo "$SD_PCREXTEND or PCR sysfs files not found, skipping PCR extension tests"
    exit 0
fi

at_exit() {
    if [[ $? -ne 0 ]]; then
        # Dump the event log on fail, to make debugging a bit easier
        jq --seq --slurp </run/log/systemd/tpm2-measure.log
    fi
}

trap at_exit EXIT

# Temporarily override sd-pcrextend's sanity checks
export SYSTEMD_FORCE_MEASURE=1

"$SD_PCREXTEND" --help
"$SD_PCREXTEND" --version
"$SD_PCREXTEND" foo
"$SD_PCREXTEND" --machine-id
"$SD_PCREXTEND" --tpm2-device=list
"$SD_PCREXTEND" --tpm2-device=auto foo
"$SD_PCREXTEND" --tpm2-device=/dev/tpm0 foo
"$SD_PCREXTEND" --bank=sha256 foo
"$SD_PCREXTEND" --bank=sha256 --bank=sha256 foo
"$SD_PCREXTEND" --graceful foo
"$SD_PCREXTEND" --pcr=15 foo
"$SD_PCREXTEND" --file-system=/
"$SD_PCREXTEND" --file-system=/tmp --file-system=/
"$SD_PCREXTEND" --file-system=/tmp --file-system=/ --pcr=15 --pcr=11

if tpm_has_pcr sha1 11; then
    "$SD_PCREXTEND" --bank=sha1 --pcr=11 foo
fi

(! "$SD_PCREXTEND")
(! "$SD_PCREXTEND" "")
(! "$SD_PCREXTEND" foo bar)
(! "$SD_PCREXTEND" --bank= foo)
(! "$SD_PCREXTEND" --tpm2-device= foo)
(! "$SD_PCREXTEND" --tpm2-device=/dev/null foo)
(! "$SD_PCREXTEND" --pcr= foo)
(! "$SD_PCREXTEND" --pcr=-1 foo)
(! "$SD_PCREXTEND" --pcr=1024 foo)
(! "$SD_PCREXTEND" --foo=bar)

unset SYSTEMD_FORCE_MEASURE

# Note: since we're reading the TPM event log as json-seq, the same rules apply to the output
#       as well, i.e. each record is prefixed by RS (0x1E, 036) and suffixed by LF (0x0A, 012).
#       LF is usually eaten by bash, but RS needs special handling.

# Save the number of events in the current event log, so we can skip them when
# checking changes caused by following tests
RECORD_COUNT="$(jq --seq --slurp '. | length' </run/log/systemd/tpm2-measure.log | tr -d '\036')"

# Let's measure the machine ID
tpm2_pcrread sha256:15 -Q -o /tmp/oldpcr15
mv /etc/machine-id /etc/machine-id.save
echo 994013bf23864ee7992eab39a96dd3bb >/etc/machine-id
SYSTEMD_FORCE_MEASURE=1 "$SD_PCREXTEND" --machine-id
mv /etc/machine-id.save /etc/machine-id
tpm2_pcrread sha256:15 -Q -o /tmp/newpcr15

# And check it matches expectations
diff /tmp/newpcr15 \
     <(cat /tmp/oldpcr15 <(echo -n "machine-id:994013bf23864ee7992eab39a96dd3bb" | openssl dgst -binary -sha256) | openssl dgst -binary -sha256)

# Check that the event log record was properly written
test "$(jq --seq --slurp ".[$RECORD_COUNT].pcr" </run/log/systemd/tpm2-measure.log)" == "$(printf '\x1e15')"
DIGEST_EXPECTED="$(echo -n "machine-id:994013bf23864ee7992eab39a96dd3bb" | openssl dgst -hex -sha256 -r)"
DIGEST_CURRENT="$(jq --seq --slurp --raw-output ".[$RECORD_COUNT].digests[] | select(.hashAlg == \"sha256\").digest" </run/log/systemd/tpm2-measure.log) *stdin"
test "$DIGEST_EXPECTED" == "$DIGEST_CURRENT"

RECORD_COUNT=$((RECORD_COUNT + 1))
# And similar for the boot phase measurement into PCR 11
tpm2_pcrread sha256:11 -Q -o /tmp/oldpcr11
# Do the equivalent of 'SYSTEMD_FORCE_MEASURE=1 "$SD_PCREXTEND" foobar' via Varlink, just to test the Varlink logic (but first we need to patch out the conditionalization...)
mkdir -p /run/systemd/system/systemd-pcrextend.socket.d
cat > /run/systemd/system/systemd-pcrextend.socket.d/50-no-condition.conf <<EOF
[Unit]
# Turn off all conditions */
ConditionSecurity=
EOF
systemctl daemon-reload
systemctl restart systemd-pcrextend.socket
varlinkctl call /run/systemd/io.systemd.PCRExtend io.systemd.PCRExtend.Extend '{"pcr":11,"text":"foobar"}'
tpm2_pcrread sha256:11 -Q -o /tmp/newpcr11

diff /tmp/newpcr11 \
    <(cat /tmp/oldpcr11 <(echo -n "foobar" | openssl dgst -binary -sha256) | openssl dgst -binary -sha256)

# Check the event log for the 2nd new record since $RECORD_COUNT
test "$(jq --seq --slurp ".[$RECORD_COUNT].pcr" </run/log/systemd/tpm2-measure.log)" == "$(printf '\x1e11')"
DIGEST_EXPECTED="$(echo -n "foobar" | openssl dgst -hex -sha256 -r)"
DIGEST_CURRENT="$(jq --seq --slurp --raw-output ".[$RECORD_COUNT].digests[] | select(.hashAlg == \"sha256\").digest" </run/log/systemd/tpm2-measure.log) *stdin"
test "$DIGEST_EXPECTED" == "$DIGEST_CURRENT"

# Measure a file system into PCR 15
tpm2_pcrread sha256:15 -Q -o /tmp/oldpcr15
SYSTEMD_FORCE_MEASURE=1 "$SD_PCREXTEND" --file-system=/
# Put together the "file system word" we just sent to the TPM
#   file-system:MOUNTPOINT:TYPE:UUID:LABEL:PART_ENTRY_UUID:PART_ENTRY_TYPE:PART_ENTRY_NAME
ROOT_DEVICE="$(findmnt -n -o SOURCE /)"
FS_WORD="$(lsblk -n -o MOUNTPOINT,FSTYPE,UUID,LABEL,PARTUUID,PARTTYPE,PARTLABEL "$ROOT_DEVICE" | sed -r 's/[ ]+/:/g')"
tpm2_pcrread sha256:15 -Q -o /tmp/newpcr15

# And check if it matches with the current PCR 15 state
diff /tmp/newpcr15 \
     <(cat /tmp/oldpcr15 <(echo -n "file-system:$FS_WORD" | openssl dgst -binary -sha256) | openssl dgst -binary -sha256)

rm -f /tmp/oldpcr{11,15} /tmp/newpcr{11,15}
