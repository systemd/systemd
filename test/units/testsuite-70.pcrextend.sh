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

rm -f /tmp/oldpcr15 /tmp/newpcr15

# Check that the event log record was properly written:
test "$(jq --seq --slurp '.[0].pcr' < /run/log/systemd/tpm2-measure.log)" == "$(printf '\x1e15')"
test "$(jq --seq --slurp --raw-output '.[0].digests[1].digest' < /run/log/systemd/tpm2-measure.log) *stdin" == "$(echo -n "machine-id:994013bf23864ee7992eab39a96dd3bb" | openssl dgst -hex -sha256 -r)"

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

# Check the event log for the 2nd record
jq --seq --slurp < /run/log/systemd/tpm2-measure.log

test "$(jq --seq --slurp .[1].pcr < /run/log/systemd/tpm2-measure.log)" == "$(printf '\x1e11')"
test "$(jq --seq --slurp --raw-output .[1].digests[0].digest < /run/log/systemd/tpm2-measure.log) *stdin" == "$(echo -n "foobar" | openssl dgst -hex -sha256 -r)"

rm -f /tmp/oldpcr11 /tmp/newpcr11
