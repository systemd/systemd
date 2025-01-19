#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

export SYSTEMD_LOG_LEVEL=debug
SD_MEASURE="/usr/lib/systemd/systemd-measure"

if [[ ! -x "${SD_MEASURE:?}" ]]; then
    echo "$SD_MEASURE not found, skipping the test"
    exit 0
fi

IMAGE="$(mktemp /tmp/systemd-measure-XXX.image)"

echo HALLO >/tmp/tpmdata1
echo foobar >/tmp/tpmdata2

cat >/tmp/result <<EOF
11:sha1=5177e4ad69db92192c10e5f80402bf81bfec8a81
11:sha256=37b48bd0b222394dbe3cceff2fca4660c4b0a90ae9369ec90b42f14489989c13
11:sha384=5573f9b2caf55b1d0a6a701f890662d682af961899f0419cf1e2d5ea4a6a68c1f25bd4f5b8a0865eeee82af90f5cb087
11:sha512=961305d7e9981d6606d1ce97b3a9a1f92610cac033e9c39064895f0e306abc1680463d55767bd98e751eae115bdef3675a9ee1d29ed37da7885b1db45bb2555b
EOF
"$SD_MEASURE" calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=: | cmp - /tmp/result

cat >/tmp/result.json <<EOF
{"sha1":[{"pcr":11,"hash":"5177e4ad69db92192c10e5f80402bf81bfec8a81"}],"sha256":[{"pcr":11,"hash":"37b48bd0b222394dbe3cceff2fca4660c4b0a90ae9369ec90b42f14489989c13"}],"sha384":[{"pcr":11,"hash":"5573f9b2caf55b1d0a6a701f890662d682af961899f0419cf1e2d5ea4a6a68c1f25bd4f5b8a0865eeee82af90f5cb087"}],"sha512":[{"pcr":11,"hash":"961305d7e9981d6606d1ce97b3a9a1f92610cac033e9c39064895f0e306abc1680463d55767bd98e751eae115bdef3675a9ee1d29ed37da7885b1db45bb2555b"}]}
EOF
"$SD_MEASURE" calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=: -j | diff -u - /tmp/result.json

cat >/tmp/result <<EOF
11:sha1=6765ee305db063040c454d32697d922b3d4f232b
11:sha256=21c49c1242042649e09c156546fd7d425ccc3c67359f840507b30be4e0f6f699
11:sha384=08d0b003a134878eee552070d51d58abe942f457ca85704131dd36f73728e7327ca837594bc9d5ac7de818d02a3d5dd2
11:sha512=65120f6ebc04b156421c6f3d543b2fad545363d9ca61c514205459e9c0e0b22e09c23605eae5853e38458ef3ca54e087168af8d8a882a98d220d9391e48be6d0
EOF
"$SD_MEASURE" calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=foo | cmp - /tmp/result

cat >/tmp/result.json <<EOF
{"sha1":[{"phase":"foo","pcr":11,"hash":"6765ee305db063040c454d32697d922b3d4f232b"}],"sha256":[{"phase":"foo","pcr":11,"hash":"21c49c1242042649e09c156546fd7d425ccc3c67359f840507b30be4e0f6f699"}],"sha384":[{"phase":"foo","pcr":11,"hash":"08d0b003a134878eee552070d51d58abe942f457ca85704131dd36f73728e7327ca837594bc9d5ac7de818d02a3d5dd2"}],"sha512":[{"phase":"foo","pcr":11,"hash":"65120f6ebc04b156421c6f3d543b2fad545363d9ca61c514205459e9c0e0b22e09c23605eae5853e38458ef3ca54e087168af8d8a882a98d220d9391e48be6d0"}]}
EOF
"$SD_MEASURE" calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=foo -j | diff -u - /tmp/result.json

rm /tmp/result /tmp/result.json

# Generate key pair
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "/tmp/pcrsign-private.pem"
openssl rsa -pubout -in "/tmp/pcrsign-private.pem" -out "/tmp/pcrsign-public.pem"

# Verify that the offline signature obtained via policy-digests is the same as an online signature created
# with the same key by systemd-measure
digest="$("$SD_MEASURE" policy-digest --json=short --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha256 --public-key="/tmp/pcrsign-public.pem" --phase=:)"
signed_digest="$("$SD_MEASURE" sign --json=short --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha256 --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=:)"
echo "$digest" | jq -r '.sha256 | to_entries[] | .value.pol' | while read -r pol; do
    # Note: basenc before coreutils 9.5 refuses lowercase hex input strings
    offline_sig="$(echo -n "$pol" | \
        tr '[:lower:]' '[:upper:]' | \
        basenc --base16 --decode | \
        openssl dgst -sign /tmp/pcrsign-private.pem -sha256 | \
        base64 -w0)"
    online_sig="$(echo "$signed_digest" | jq -r --arg pol "$pol" '.sha256[] | select(.pol == $pol) | .sig')"
    test -n "$offline_sig"
    test -n "$online_sig"
    test "$offline_sig" = "$online_sig"
done

if ! tpm_has_pcr sha1 11 || ! tpm_has_pcr sha256 11; then
    echo "PCR sysfs files not found, skipping signed PCR policy tests"
    exit 0
fi

MEASURE_BANKS=("--bank=sha256")
# Check if SHA1 signatures are supported
#
# Some distros have started phasing out SHA1, so make sure the SHA1
# signatures are supported before trying to use them.
if echo hello | openssl dgst -sign /tmp/pcrsign-private.pem -sha1 >/dev/null; then
    MEASURE_BANKS+=("--bank=sha1")
fi

# Sign current PCR state with it
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: | tee "/tmp/pcrsign.sig"
dd if=/dev/urandom of=/tmp/pcrtestdata bs=1024 count=64
systemd-creds encrypt /tmp/pcrtestdata /tmp/pcrtestdata.encrypted --with-key=host+tpm2-with-public-key --tpm2-public-key="/tmp/pcrsign-public.pem"
systemd-creds decrypt /tmp/pcrtestdata.encrypted - --tpm2-signature="/tmp/pcrsign.sig" | cmp - /tmp/pcrtestdata

# Invalidate PCR, decrypting should fail now
tpm2_pcrextend 11:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! systemd-creds decrypt /tmp/pcrtestdata.encrypted - --tpm2-signature="/tmp/pcrsign.sig" >/dev/null)

# Sign new PCR state, decrypting should work now.
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: >"/tmp/pcrsign.sig2"
systemd-creds decrypt /tmp/pcrtestdata.encrypted - --tpm2-signature="/tmp/pcrsign.sig2" | cmp - /tmp/pcrtestdata

# Now, do the same, but with a cryptsetup binding
truncate -s 20M "$IMAGE"
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$IMAGE" /tmp/passphrase
# Ensure that an unrelated signature, when not requested, is not used
touch /run/systemd/tpm2-pcr-signature.json
systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto --tpm2-public-key="/tmp/pcrsign-public.pem" "$IMAGE"
# Reset and use the signature now
rm -f /run/systemd/tpm2-pcr-signature.json
systemd-cryptenroll --wipe-slot=tpm2 "$IMAGE"
systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto --tpm2-public-key="/tmp/pcrsign-public.pem" --tpm2-signature="/tmp/pcrsign.sig2" "$IMAGE"

# Check if we can activate that (without the token module stuff)
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup detach test-volume2

# Check if we can activate that (and a second time with the token module stuff enabled)
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup detach test-volume2

# After extending the PCR things should fail
tpm2_pcrextend 11:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1)
(! SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1)

# But once we sign the current PCRs, we should be able to unlock again
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: >"/tmp/pcrsign.sig3"
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig3",headless=1
systemd-cryptsetup detach test-volume2
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig3",headless=1
systemd-cryptsetup detach test-volume2

# Test --append mode and de-duplication. With the same parameters signing should not add a new entry
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: --append="/tmp/pcrsign.sig3" >"/tmp/pcrsign.sig4"
cmp "/tmp/pcrsign.sig3" "/tmp/pcrsign.sig4"

# Sign one more phase, this should
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=quux:waldo --append="/tmp/pcrsign.sig4" >"/tmp/pcrsign.sig5"
(! cmp "/tmp/pcrsign.sig4" "/tmp/pcrsign.sig5")

# Should still be good to unlock, given the old entry still exists
SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$IMAGE" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig5",headless=1
systemd-cryptsetup detach test-volume2

# Adding both signatures once more should not change anything, due to the deduplication
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: --append="/tmp/pcrsign.sig5" >"/tmp/pcrsign.sig6"
"$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=quux:waldo --append="/tmp/pcrsign.sig6" >"/tmp/pcrsign.sig7"
cmp "/tmp/pcrsign.sig5" "/tmp/pcrsign.sig7"

rm -f "$IMAGE"
