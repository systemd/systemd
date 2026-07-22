#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Tests that systemd-cryptsetup's tpm2-measure-pcr=/tpm2-measure-keyslot-nvpcr=
# options measure the volume key and unlock keyslot through the io.systemd.PCRExtend Varlink service.

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

if ! command -v systemd-cryptsetup >/dev/null || ! tpm_has_pcr sha256 15; then
    echo "systemd-cryptsetup or PCR 15 (sha256) not available, skipping cryptsetup measurement test"
    exit 0
fi

IMAGE=""

at_exit() {
    if [[ $? -ne 0 ]]; then
        # Dump the event log on failure, to ease debugging
        jq --seq --slurp </run/log/systemd/tpm2-measure.log || :
    fi

    set +e

    systemd-cryptsetup detach test-volume
    rm -rf /run/systemd/system/systemd-pcrextend.socket.d
    systemctl daemon-reload
    systemctl restart systemd-pcrextend.socket
    rm -f "${IMAGE:-}" /tmp/passphrase /tmp/vk /tmp/vk-hmac.bin \
          /tmp/oldpcr15 /tmp/newpcr15 /tmp/measure-bank.log
}

trap at_exit EXIT

# The socket carries ConditionSecurity=measured-os, which does not hold in the
# test VM, so the Varlink service would never activate. Drop the condition so
# systemd-cryptsetup can reach it, exactly like TEST-70-TPM2.pcrextend.sh does.
mkdir -p /run/systemd/system/systemd-pcrextend.socket.d
cat >/run/systemd/system/systemd-pcrextend.socket.d/50-no-condition.conf <<EOF
[Unit]
ConditionSecurity=
EOF
systemctl daemon-reload
systemctl restart systemd-pcrextend.socket

# Prepare a fresh LUKS2 volume unlocked by a passphrase keyfile
IMAGE="$(mktemp /tmp/systemd-cryptsetup-measure-XXX.IMAGE)"
truncate -s 20M "$IMAGE"
echo -n passphrase >/tmp/passphrase
chmod 0600 /tmp/passphrase
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$IMAGE" /tmp/passphrase

UUID="$(cryptsetup luksUUID "$IMAGE")"

# Extract the raw volume key so we can recompute the expected HMAC below. The
# volume key is measured as HMAC(volume_key, prefix) rather than a plain hash
# (see cryptsetup_get_volume_key_prefix()/cryptsetup_get_volume_key_id()).
cryptsetup luksDump -q --dump-volume-key --volume-key-file=/tmp/vk --key-file=/tmp/passphrase "$IMAGE"
VK_HEX="$(od -An -v -tx1 /tmp/vk | tr -d ' \n')"

# prefix = "cryptsetup:" <escaped volume name> ":" <LUKS UUID>; "test-volume"
# contains no ':' so it is unescaped.
PREFIX="cryptsetup:test-volume:$UUID"

# Expected measured digest for the sha256 bank: HMAC-SHA256(volume_key, prefix)
printf '%s' "$PREFIX" | openssl dgst -binary -sha256 -mac HMAC -macopt "hexkey:$VK_HEX" >/tmp/vk-hmac.bin
DIGEST_EXPECTED="$(od -An -v -tx1 /tmp/vk-hmac.bin | tr -d ' \n')"

# Remember the current event log length so we can index the record we add.
# (json-seq: each record is RS(0x1e)-prefixed, LF-suffixed.)
RECORD_COUNT="$(jq --seq --slurp '. | length' </run/log/systemd/tpm2-measure.log | tr -d '\036')"

tpm2_pcrread sha256:15 -Q -o /tmp/oldpcr15

# Activate with measurement enabled. Unlock is via the keyfile (no TPM unlock),
# to prove measurement is independent of the unlock mechanism.
SYSTEMD_FORCE_MEASURE=1 systemd-cryptsetup attach test-volume "$IMAGE" /tmp/passphrase \
    tpm2-measure-pcr=15,tpm2-measure-keyslot-nvpcr=cryptsetup,headless=1

tpm2_pcrread sha256:15 -Q -o /tmp/newpcr15

# The TPM PCR 15 must have been extended with the HMAC:
#   new = sha256(old || HMAC(volume_key, prefix))
diff /tmp/newpcr15 \
     <(cat /tmp/oldpcr15 /tmp/vk-hmac.bin | openssl dgst -binary -sha256)

# The volume-key measurement is the first new record (it runs before the keyslot
# one, and before any NvPCR-init records the keyslot path may add).
test "$(jq --seq --slurp ".[$RECORD_COUNT].pcr" </run/log/systemd/tpm2-measure.log)" == "$(printf '\x1e15')"
DIGEST_CURRENT="$(jq --seq --slurp --raw-output ".[$RECORD_COUNT].digests[] | select(.hashAlg == \"sha256\").digest" </run/log/systemd/tpm2-measure.log)"
test "$DIGEST_CURRENT" == "$DIGEST_EXPECTED"

# The keyslot measurement went into the "cryptsetup" NvPCR; check its record's
# measured string (content-based, since its exact index depends on whether the
# NvPCR had to be anchored first).
KEYSLOT_STRING="$(jq --seq --slurp --raw-output '[.[] | select(.content.nvIndexName == "cryptsetup") | .content.string] | last' </run/log/systemd/tpm2-measure.log)"
[[ "$KEYSLOT_STRING" == "cryptsetup-keyslot:test-volume:$UUID:"* ]]

systemd-cryptsetup detach test-volume

# The deprecated tpm2-measure-bank= option must warn but not fail.
SYSTEMD_FORCE_MEASURE=1 systemd-cryptsetup attach test-volume "$IMAGE" /tmp/passphrase \
    tpm2-measure-pcr=15,tpm2-measure-bank=sha256,headless=1 |& tee /tmp/measure-bank.log
systemd-cryptsetup detach test-volume
grep -i "deprecated" /tmp/measure-bank.log >/dev/null
