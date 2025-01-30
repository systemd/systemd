#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug

cryptsetup_has_token_plugin_support() {
    local plugin_path

    plugin_path="$(cryptsetup --help | sed -nr 's/.*LUKS2 external token plugin path: (.*)\./\1/p')/libcryptsetup-token-systemd-tpm2.so)"
    cryptsetup --help | grep -q 'LUKS2 external token plugin support is compiled-in' && [[ -f "$plugin_path" ]]
}

tpm_check_failure_with_wrong_pin() {
    local testIMAGE="${1:?}"
    local badpin="${2:?}"
    local goodpin="${3:?}"

    # We need to be careful not to trigger DA lockout; allow 2 failures
    tpm2_dictionarylockout -s -n 2
    (! PIN=$badpin systemd-cryptsetup attach test-volume "$testIMAGE" - tpm2-device=auto,headless=1)
    # Verify the correct PIN works, to be sure the failure wasn't a DA lockout
    PIN=$goodpin systemd-cryptsetup attach test-volume "$testIMAGE" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume
    # Clear/reset the DA lockout counter
    tpm2_dictionarylockout -c
}

at_exit() {
    # Evict the TPM primary key that we persisted
    if [[ -n "${PERSISTENT_HANDLE:-}" ]]; then
        tpm2_evictcontrol -c "$PERSISTENT_HANDLE"
    fi
}

trap at_exit EXIT

# Prepare a fresh disk image
IMAGE="$(mktemp /tmp/systemd-cryptsetup-XXX.IMAGE)"

truncate -s 20M "$IMAGE"
echo -n passphrase >/tmp/passphrase
# Change file mode to avoid "/tmp/passphrase has 0644 mode that is too permissive" messages
chmod 0600 /tmp/passphrase
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$IMAGE" /tmp/passphrase

# Unlocking via keyfile
systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto --tpm2-pcrs=7 "$IMAGE"

# Enroll unlock with SecureBoot (PCR 7) PCR policy
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Check with wrong PCR
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1)

# Enroll unlock with PCR+PIN policy
systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=true --tpm2-pcrs=7 "$IMAGE"
PIN=123456 systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Check failure with wrong PIN; try a few times to make sure we avoid DA lockout
for _ in {0..3}; do
    tpm_check_failure_with_wrong_pin "$IMAGE" 123457 123456
done

# Check LUKS2 token plugin unlock (i.e. without specifying tpm2-device=auto)
if cryptsetup_has_token_plugin_support; then
    PIN=123456 systemd-cryptsetup attach test-volume "$IMAGE" - headless=1
    systemd-cryptsetup detach test-volume

    # Check failure with wrong PIN
    for _ in {0..3}; do
        tpm_check_failure_with_wrong_pin "$IMAGE" 123457 123456
    done
else
    echo 'cryptsetup has no LUKS2 token plugin support, skipping'
fi

# Check failure with wrong PCR (and correct PIN)
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! PIN=123456 systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1)

# Enroll unlock with PCR 0+7
systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Check with wrong PCR 0
tpm2_pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1)

if tpm_has_pcr sha256 12; then
    # Enroll using an explicit PCR value (that does match current PCR value)
    systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
    EXPECTED_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="12:sha256=$EXPECTED_PCR_VALUE" "$IMAGE"
    systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # Same as above plus more PCRs without the value or alg specified
    systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
    EXPECTED_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="1,12:sha256=$EXPECTED_PCR_VALUE,3" "$IMAGE"
    systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # Same as above plus more PCRs with hash alg specified but hash value not specified
    systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
    EXPECTED_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="1:sha256,12:sha256=$EXPECTED_PCR_VALUE,3" "$IMAGE"
    systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # Now the interesting part, enrolling using a hash value that doesn't match the current PCR value
    systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
    tpm2_pcrread -Q -o /tmp/pcr.dat sha256:12
    CURRENT_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    EXPECTED_PCR_VALUE=$(cat /tmp/pcr.dat /tmp/pcr.dat | openssl dgst -sha256 -r | cut -d ' ' -f 1)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="12:sha256=$EXPECTED_PCR_VALUE" "$IMAGE"
    (! systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1)
    tpm2_pcrextend "12:sha256=$CURRENT_PCR_VALUE"
    systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # enroll TPM using device key instead of direct access, then verify unlock using TPM
    tpm2_pcrread -Q -o /tmp/pcr.dat sha256:12
    CURRENT_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    tpm2_readpublic -c 0x81000001 -o /tmp/srk.pub
    systemd-analyze srk > /tmp/srk2.pub
    cmp /tmp/srk.pub /tmp/srk2.pub
    if [ -f /run/systemd/tpm2-srk-public-key.tpm2b_public ] ; then
        cmp /tmp/srk.pub /run/systemd/tpm2-srk-public-key.tpm2b_public
    fi

    # --tpm2-device-key= requires OpenSSL >= 3 with KDF-SS
    if openssl_supports_kdf SSKDF; then
        PASSWORD=passphrase systemd-cryptenroll --tpm2-device-key=/tmp/srk.pub --tpm2-pcrs="12:sha256=$CURRENT_PCR_VALUE" "$IMAGE"
        systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
        systemd-cryptsetup detach test-volume
    fi

    rm -f /tmp/pcr.dat /tmp/srk.pub
fi

# Use default (0) seal key handle
systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0 "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0x0 "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Use SRK seal key handle
systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=81000001 "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0x81000001 "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Test invalid ranges: pcr, nv, session, permanent
systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
(! PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=7 "$IMAGE")          # PCR
(! PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0x01000001 "$IMAGE") # NV index
(! PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0x02000001 "$IMAGE") # HMAC/loaded session
(! PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0x03000001 "$IMAGE") # Policy/saved session
(! PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle=0x40000001 "$IMAGE") # Permanent

# Use non-SRK persistent seal key handle (by creating/persisting new key)
PRIMARY=/tmp/primary.ctx
tpm2_createprimary -c "$PRIMARY"
PERSISTENT_LINE=$(tpm2_evictcontrol -c "$PRIMARY" | grep persistent-handle)
PERSISTENT_HANDLE="0x${PERSISTENT_LINE##*0x}"
tpm2_flushcontext -t

systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle="${PERSISTENT_HANDLE#0x}" "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-seal-key-handle="$PERSISTENT_HANDLE" "$IMAGE"
systemd-cryptsetup attach test-volume "$IMAGE" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# --tpm2-device-key= requires OpenSSL >= 3 with KDF-SS
if openssl_supports_kdf SSKDF; then
    # Make sure that --tpm2-device-key= also works with systemd-repart
    tpm2_readpublic -c 0x81000001 -o /tmp/srk.pub
    mkdir /tmp/dditest
    cat > /tmp/dditest/50-root.conf <<EOF
[Partition]
Type=root
Format=ext4
CopyFiles=/tmp/dditest:/
Encrypt=tpm2
EOF
    PASSWORD=passphrase systemd-repart --tpm2-device-key=/tmp/srk.pub --definitions=/tmp/dditest --empty=create --size=80M /tmp/dditest.raw --tpm2-pcrs=
    DEVICE="$(systemd-dissect --attach /tmp/dditest.raw)"
    udevadm wait --settle --timeout=10 "$DEVICE"p1
    systemd-cryptsetup attach dditest "$DEVICE"p1 - tpm2-device=auto,headless=yes
    mkdir /tmp/dditest.mnt
    mount -t ext4 /dev/mapper/dditest /tmp/dditest.mnt
    cmp /tmp/dditest.mnt/50-root.conf /tmp/dditest/50-root.conf
    umount /tmp/dditest.mnt
    rmdir /tmp/dditest.mnt
    rm /tmp/dditest.raw
    rm /tmp/dditest/50-root.conf
    rmdir /tmp/dditest
fi

rm -f "$IMAGE" "$PRIMARY"
