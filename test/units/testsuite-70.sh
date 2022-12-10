#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

# Prepare fresh disk image
img="/var/tmp/test.img"
truncate -s 20M $img
echo -n passphrase >/tmp/passphrase
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom $img /tmp/passphrase

# Unlocking via keyfile
systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto $img

# Enroll unlock with default PCR policy
env PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto $img
/usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1
/usr/lib/systemd/systemd-cryptsetup detach test-volume

# Check with wrong PCR
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
/usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1 && { echo 'unexpected success'; exit 1; }

# Enroll unlock with PCR+PIN policy
systemd-cryptenroll --wipe-slot=tpm2 $img
env PASSWORD=passphrase NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=true $img
env PIN=123456 /usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1
/usr/lib/systemd/systemd-cryptsetup detach test-volume

# Check failure with wrong PIN
env PIN=123457 /usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1 && { echo 'unexpected success'; exit 1; }

# Check LUKS2 token plugin unlock (i.e. without specifying tpm2-device=auto)
if cryptsetup --help | grep -q 'LUKS2 external token plugin support is compiled-in' && \
         [ -f "$(cryptsetup --help | sed -n -r 's/.*LUKS2 external token plugin path: (.*)\./\1/p')/libcryptsetup-token-systemd-tpm2.so" ]; then
    env PIN=123456 /usr/lib/systemd/systemd-cryptsetup attach test-volume $img - headless=1
    /usr/lib/systemd/systemd-cryptsetup detach test-volume

    # Check failure with wrong PIN
    env PIN=123457 /usr/lib/systemd/systemd-cryptsetup attach test-volume $img - headless=1 && { echo 'unexpected success'; exit 1; }
else
    echo 'cryptsetup has no LUKS2 token plugin support, skipping'
fi

# Check failure with wrong PCR (and correct PIN)
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
env PIN=123456 /usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1 && { echo 'unexpected success'; exit 1; }

# Enroll unlock with PCR 0+7
systemd-cryptenroll --wipe-slot=tpm2 $img
env PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 $img
/usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1
/usr/lib/systemd/systemd-cryptsetup detach test-volume

# Check with wrong PCR 0
tpm2_pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000
/usr/lib/systemd/systemd-cryptsetup attach test-volume $img - tpm2-device=auto,headless=1 && exit 1

rm $img

if [[ -e /usr/lib/systemd/systemd-measure ]]; then
    echo HALLO > /tmp/tpmdata1
    echo foobar > /tmp/tpmdata2

    cat >/tmp/result <<EOF
11:sha1=5177e4ad69db92192c10e5f80402bf81bfec8a81
11:sha256=37b48bd0b222394dbe3cceff2fca4660c4b0a90ae9369ec90b42f14489989c13
11:sha384=5573f9b2caf55b1d0a6a701f890662d682af961899f0419cf1e2d5ea4a6a68c1f25bd4f5b8a0865eeee82af90f5cb087
11:sha512=961305d7e9981d6606d1ce97b3a9a1f92610cac033e9c39064895f0e306abc1680463d55767bd98e751eae115bdef3675a9ee1d29ed37da7885b1db45bb2555b
EOF
    /usr/lib/systemd/systemd-measure calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=: | cmp - /tmp/result

    cat >/tmp/result.json <<EOF
{"sha1":[{"pcr":11,"hash":"5177e4ad69db92192c10e5f80402bf81bfec8a81"}],"sha256":[{"pcr":11,"hash":"37b48bd0b222394dbe3cceff2fca4660c4b0a90ae9369ec90b42f14489989c13"}],"sha384":[{"pcr":11,"hash":"5573f9b2caf55b1d0a6a701f890662d682af961899f0419cf1e2d5ea4a6a68c1f25bd4f5b8a0865eeee82af90f5cb087"}],"sha512":[{"pcr":11,"hash":"961305d7e9981d6606d1ce97b3a9a1f92610cac033e9c39064895f0e306abc1680463d55767bd98e751eae115bdef3675a9ee1d29ed37da7885b1db45bb2555b"}]}
EOF
    /usr/lib/systemd/systemd-measure calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=: -j | diff -u - /tmp/result.json

    cat >/tmp/result <<EOF
11:sha1=6765ee305db063040c454d32697d922b3d4f232b
11:sha256=21c49c1242042649e09c156546fd7d425ccc3c67359f840507b30be4e0f6f699
11:sha384=08d0b003a134878eee552070d51d58abe942f457ca85704131dd36f73728e7327ca837594bc9d5ac7de818d02a3d5dd2
11:sha512=65120f6ebc04b156421c6f3d543b2fad545363d9ca61c514205459e9c0e0b22e09c23605eae5853e38458ef3ca54e087168af8d8a882a98d220d9391e48be6d0
EOF
    /usr/lib/systemd/systemd-measure calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=foo | cmp - /tmp/result

    cat >/tmp/result.json <<EOF
{"sha1":[{"phase":"foo","pcr":11,"hash":"6765ee305db063040c454d32697d922b3d4f232b"}],"sha256":[{"phase":"foo","pcr":11,"hash":"21c49c1242042649e09c156546fd7d425ccc3c67359f840507b30be4e0f6f699"}],"sha384":[{"phase":"foo","pcr":11,"hash":"08d0b003a134878eee552070d51d58abe942f457ca85704131dd36f73728e7327ca837594bc9d5ac7de818d02a3d5dd2"}],"sha512":[{"phase":"foo","pcr":11,"hash":"65120f6ebc04b156421c6f3d543b2fad545363d9ca61c514205459e9c0e0b22e09c23605eae5853e38458ef3ca54e087168af8d8a882a98d220d9391e48be6d0"}]}
EOF
    /usr/lib/systemd/systemd-measure calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 --phase=foo -j | diff -u - /tmp/result.json

    rm /tmp/result /tmp/result.json
else
    echo "/usr/lib/systemd/systemd-measure not found, skipping PCR policy test case"
fi

if [ -e /usr/lib/systemd/systemd-measure ] && \
         [ -f /sys/class/tpm/tpm0/pcr-sha1/11 ] && \
         [ -f /sys/class/tpm/tpm0/pcr-sha256/11 ]; then
    # Generate key pair
    openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "/tmp/pcrsign-private.pem"
    openssl rsa -pubout -in "/tmp/pcrsign-private.pem" -out "/tmp/pcrsign-public.pem"

    MEASURE_BANKS=("--bank=sha256")
    # Check if SHA1 signatures are supported
    #
    # Some distros have started phasing out SHA1, so make sure the SHA1
    # signatures are supported before trying to use them.
    if echo hello | openssl dgst -sign /tmp/pcrsign-private.pem -sha1 >/dev/null; then
        MEASURE_BANKS+=("--bank=sha1")
    fi

    # Sign current PCR state with it
    /usr/lib/systemd/systemd-measure sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: | tee "/tmp/pcrsign.sig"
    dd if=/dev/urandom of=/tmp/pcrtestdata bs=1024 count=64
    systemd-creds encrypt /tmp/pcrtestdata /tmp/pcrtestdata.encrypted --with-key=host+tpm2-with-public-key --tpm2-public-key="/tmp/pcrsign-public.pem"
    systemd-creds decrypt /tmp/pcrtestdata.encrypted - --tpm2-signature="/tmp/pcrsign.sig" | cmp - /tmp/pcrtestdata

    # Invalidate PCR, decrypting should fail now
    tpm2_pcrextend 11:sha256=0000000000000000000000000000000000000000000000000000000000000000
    systemd-creds decrypt /tmp/pcrtestdata.encrypted - --tpm2-signature="/tmp/pcrsign.sig" > /dev/null && { echo 'unexpected success'; exit 1; }

    # Sign new PCR state, decrypting should work now.
    /usr/lib/systemd/systemd-measure sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: > "/tmp/pcrsign.sig2"
    systemd-creds decrypt /tmp/pcrtestdata.encrypted - --tpm2-signature="/tmp/pcrsign.sig2" | cmp - /tmp/pcrtestdata

    # Now, do the same, but with a cryptsetup binding
    truncate -s 20M $img
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom $img /tmp/passphrase
    systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto --tpm2-public-key="/tmp/pcrsign-public.pem" --tpm2-signature="/tmp/pcrsign.sig2" $img

    # Check if we can activate that (without the token module stuff)
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 /usr/lib/systemd/systemd-cryptsetup attach test-volume2 $img - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 /usr/lib/systemd/systemd-cryptsetup detach test-volume2

    # Check if we can activate that (and a second time with the the token module stuff enabled)
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 /usr/lib/systemd/systemd-cryptsetup attach test-volume2 $img - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 /usr/lib/systemd/systemd-cryptsetup detach test-volume2

    # After extending the PCR things should fail
    tpm2_pcrextend 11:sha256=0000000000000000000000000000000000000000000000000000000000000000
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 /usr/lib/systemd/systemd-cryptsetup attach test-volume2 $img - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1 && { echo 'unexpected success'; exit 1; }
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 /usr/lib/systemd/systemd-cryptsetup attach test-volume2 $img - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1 && { echo 'unexpected success'; exit 1; }

    # But once we sign the current PCRs, we should be able to unlock again
    /usr/lib/systemd/systemd-measure sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: > "/tmp/pcrsign.sig3"
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 /usr/lib/systemd/systemd-cryptsetup attach test-volume2 $img - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig3",headless=1
    /usr/lib/systemd/systemd-cryptsetup detach test-volume2
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 /usr/lib/systemd/systemd-cryptsetup attach test-volume2 $img - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig3",headless=1
    /usr/lib/systemd/systemd-cryptsetup detach test-volume2

    rm $img
else
    echo "/usr/lib/systemd/systemd-measure or PCR sysfs files not found, skipping signed PCR policy test case"
fi

echo OK >/testok

exit 0
