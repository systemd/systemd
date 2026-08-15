#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

cryptenroll_wipe_and_check() {(
    set +o pipefail

    : >/tmp/cryptenroll.out
    systemd-cryptenroll "$@" |& tee /tmp/cryptenroll.out
    grep -qE "Wiped slot [[:digit:]]+" /tmp/cryptenroll.out
)}

at_exit() {
    rm -f "${IMAGE:-}" "${VL_IMAGE:-}" /tmp/cryptenroll.out /tmp/password
}

trap at_exit EXIT

# There is an external issue with libcryptsetup on ppc64 that hits 95% of Ubuntu ppc64 test runs, so skip it
if [[ "$(uname -m)" == "ppc64le" ]]; then
    echo "Skipping systemd-cryptenroll tests on ppc64le, see https://github.com/systemd/systemd/issues/27716"
    exit 0
fi

export SYSTEMD_LOG_LEVEL=debug
IMAGE="$(mktemp /tmp/systemd-cryptenroll-XXX.image)"

truncate -s 20M "$IMAGE"
echo -n password >/tmp/password
# Change file mode to avoid "/tmp/password has 0644 mode that is too permissive" messages
chmod 0600 /tmp/password
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$IMAGE" /tmp/password

# Enroll additional tokens, keys, and passwords to exercise the list and wipe stuff
# Use --tpm2-public-key= to suppress auto-loading any PCR public key from the host
systemd-cryptenroll --unlock-key-file=/tmp/password --tpm2-device=auto --tpm2-public-key= "$IMAGE"
NEWPASSWORD="" systemd-cryptenroll --unlock-key-file=/tmp/password  --password "$IMAGE"
NEWPASSWORD=foo systemd-cryptenroll --unlock-key-file=/tmp/password  --password "$IMAGE"
for _ in {0..9}; do
    systemd-cryptenroll --unlock-key-file=/tmp/password --recovery-key "$IMAGE"
done
PASSWORD="" NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-public-key= --tpm2-with-pin=true "$IMAGE"
# Do some basic checks before we start wiping stuff
systemd-cryptenroll "$IMAGE"
systemd-cryptenroll "$IMAGE" | grep password
systemd-cryptenroll "$IMAGE" | grep recovery
# Let's start wiping
cryptenroll_wipe_and_check "$IMAGE" --wipe=empty
(! cryptenroll_wipe_and_check "$IMAGE" --wipe=empty)
cryptenroll_wipe_and_check "$IMAGE" --wipe=empty,0
PASSWORD=foo NEWPASSWORD=foo cryptenroll_wipe_and_check "$IMAGE" --wipe=0,0,empty,0,pkcs11,fido2,000,recovery,password --password
systemd-cryptenroll "$IMAGE" | grep password
(! systemd-cryptenroll "$IMAGE" | grep recovery)
# We shouldn't be able to wipe all keyslots without enrolling a new key first
(! systemd-cryptenroll "$IMAGE" --wipe=all)
PASSWORD=foo NEWPASSWORD=foo cryptenroll_wipe_and_check "$IMAGE" --password --wipe=all
# Check if the newly (and only) enrolled password works
(! systemd-cryptenroll --unlock-key-file=/tmp/password --recovery-key "$IMAGE")
(! PASSWORD="" systemd-cryptenroll --recovery-key "$IMAGE")
PASSWORD=foo systemd-cryptenroll --recovery-key "$IMAGE"

systemd-cryptenroll --fido2-with-client-pin=false "$IMAGE"
systemd-cryptenroll --fido2-with-user-presence=false "$IMAGE"
systemd-cryptenroll --fido2-with-user-verification=false "$IMAGE"
systemd-cryptenroll --tpm2-pcrs=8 "$IMAGE"
systemd-cryptenroll --tpm2-pcrs=boot-loader-code+boot-loader-config "$IMAGE"

# Unlocking using TPM2
PASSWORD=foo systemd-cryptenroll --tpm2-device=auto --tpm2-public-key= "$IMAGE"
systemd-cryptenroll --unlock-tpm2-device=auto --recovery-key "$IMAGE"
systemd-cryptenroll --unlock-tpm2-device=auto --tpm2-device=auto --tpm2-public-key= --wipe-slot=tpm2 "$IMAGE"

# Add PIN to TPM2 enrollment
NEWPIN=1234 systemd-cryptenroll --unlock-tpm2-device=auto --tpm2-device=auto --tpm2-public-key= --tpm2-with-pin=yes "$IMAGE"

# Change PIN on TPM2 enrollment
PIN=1234 NEWPIN=4321 systemd-cryptenroll --unlock-tpm2-device=auto --tpm2-device=auto --tpm2-public-key= --tpm2-with-pin=yes "$IMAGE"
PIN=4321 systemd-cryptenroll --unlock-tpm2-device=auto --recovery-key "$IMAGE"

(! systemd-cryptenroll --fido2-with-client-pin=false)
(! systemd-cryptenroll --fido2-with-user-presence=f "$IMAGE" /tmp/foo)
(! systemd-cryptenroll --fido2-with-client-pin=1234 "$IMAGE")
(! systemd-cryptenroll --fido2-with-user-presence=1234 "$IMAGE")
(! systemd-cryptenroll --fido2-with-user-verification=1234 "$IMAGE")
(! systemd-cryptenroll --tpm2-with-pin=1234 "$IMAGE")
(! systemd-cryptenroll --recovery-key --password "$IMAGE")
(! systemd-cryptenroll --password --recovery-key "$IMAGE")
(! systemd-cryptenroll --password --fido2-device=auto "$IMAGE")
(! systemd-cryptenroll --password --pkcs11-token-uri=auto "$IMAGE")
(! systemd-cryptenroll --password --tpm2-device=auto "$IMAGE")
(! systemd-cryptenroll --unlock-fido2-device=auto --unlock-fido2-device=auto "$IMAGE")
(! systemd-cryptenroll --unlock-fido2-device=auto --unlock-key-file=/tmp/unlock "$IMAGE")
(! systemd-cryptenroll --fido2-credential-algorithm=es512 "$IMAGE")
(! systemd-cryptenroll --tpm2-public-key-pcrs=key "$IMAGE")
(! systemd-cryptenroll --tpm2-pcrs=key "$IMAGE")
(! systemd-cryptenroll --tpm2-pcrs=44+8 "$IMAGE")
(! systemd-cryptenroll --tpm2-pcrs=hello "$IMAGE")
(! systemd-cryptenroll --wipe-slot "$IMAGE")
(! systemd-cryptenroll --wipe-slot=10240000 "$IMAGE")
(! systemd-cryptenroll --fido2-device=auto --unlock-fido2-device=auto "$IMAGE")

rm -f "$IMAGE"

# Exercise the io.systemd.CryptEnroll Varlink interface with calls equivalent to the command line ones above.
CRYPTENROLL="$(command -v systemd-cryptenroll)"
VL_ADDRESS="exec:$CRYPTENROLL"
VL_IMAGE="$(mktemp /tmp/systemd-cryptenroll-varlink-XXX.image)"
truncate -s 20M "$VL_IMAGE"
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$VL_IMAGE" /tmp/password

# Enroll a recovery key, unlocking via key file (cf. systemd-cryptenroll --unlock-key-file= --recovery-key)
varlinkctl call "$VL_ADDRESS" io.systemd.CryptEnroll.Enroll \
    "{\"node\":\"$VL_IMAGE\",\"mechanism\":\"recovery\",\"unlockKeyFile\":\"/tmp/password\"}" | grep recoveryKey >/dev/null

# Enroll a password, unlocking via key file (cf. NEWPASSWORD=… systemd-cryptenroll --unlock-key-file= --password)
varlinkctl call "$VL_ADDRESS" io.systemd.CryptEnroll.Enroll \
    "{\"node\":\"$VL_IMAGE\",\"mechanism\":\"password\",\"unlockKeyFile\":\"/tmp/password\",\"password\":\"varlinkpassword\"}"

# Enroll a password, unlocking via the key file passed as a file descriptor instead of a path
varlinkctl --push-fd=3 call "$VL_ADDRESS" io.systemd.CryptEnroll.Enroll \
    "{\"node\":\"$VL_IMAGE\",\"mechanism\":\"password\",\"unlockKeyFileDescriptor\":0,\"password\":\"fdpassword\"}" 3</tmp/password

# List enrolled slots (must be called with 'more'); we should see the password and recovery slots
varlinkctl call --more "$VL_ADDRESS" io.systemd.CryptEnroll.ListSlots "{\"node\":\"$VL_IMAGE\"}" | grep '"type":"recovery"' >/dev/null
varlinkctl call --more "$VL_ADDRESS" io.systemd.CryptEnroll.ListSlots "{\"node\":\"$VL_IMAGE\"}" | grep '"type":"password"' >/dev/null

# Enroll combined with a wipe of the recovery key slot (cf. systemd-cryptenroll --wipe-slot=recovery --password).
# The recovery key slot just got wiped, so it should be reported back in the (non-empty) wipedSlots output.
varlinkctl call "$VL_ADDRESS" io.systemd.CryptEnroll.Enroll \
    "{\"node\":\"$VL_IMAGE\",\"mechanism\":\"password\",\"unlockKeyFile\":\"/tmp/password\",\"password\":\"wipepassword\",\"wipeTypes\":[\"recovery\"]}" | grep -E '"wipedSlots":\[[0-9]+(,[0-9]+)*\]' >/dev/null
(! varlinkctl call --more "$VL_ADDRESS" io.systemd.CryptEnroll.ListSlots "{\"node\":\"$VL_IMAGE\"}" | grep '"type":"recovery"' >/dev/null)

# ListSlots without 'more' is refused
(! varlinkctl call "$VL_ADDRESS" io.systemd.CryptEnroll.ListSlots "{\"node\":\"$VL_IMAGE\"}")

# PKCS#11 and TPM2 cannot be enrolled via this interface, so the Enroll() handler rejects them as invalid parameters
(! varlinkctl call "$VL_ADDRESS" io.systemd.CryptEnroll.Enroll \
    "{\"node\":\"$VL_IMAGE\",\"mechanism\":\"tpm2\",\"unlockKeyFile\":\"/tmp/password\"}")
(! varlinkctl call "$VL_ADDRESS" io.systemd.CryptEnroll.Enroll \
    "{\"node\":\"$VL_IMAGE\",\"mechanism\":\"pkcs11\",\"unlockKeyFile\":\"/tmp/password\"}")

rm -f "$VL_IMAGE"
