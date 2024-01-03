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
systemd-cryptenroll --unlock-key-file=/tmp/password --tpm2-device=auto "$IMAGE"
NEWPASSWORD="" systemd-cryptenroll --unlock-key-file=/tmp/password  --password "$IMAGE"
NEWPASSWORD=foo systemd-cryptenroll --unlock-key-file=/tmp/password  --password "$IMAGE"
for _ in {0..9}; do
    systemd-cryptenroll --unlock-key-file=/tmp/password --recovery-key "$IMAGE"
done
PASSWORD="" NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=true "$IMAGE"
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
PASSWORD=foo systemd-cryptenroll --tpm2-device=auto "$IMAGE"
systemd-cryptenroll --unlock-tpm2-device=auto --recovery-key "$IMAGE"
systemd-cryptenroll --unlock-tpm2-device=auto --tpm2-device=auto --wipe-slot=tpm2 "$IMAGE"

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
