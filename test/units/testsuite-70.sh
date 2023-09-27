#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

SD_MEASURE="/usr/lib/systemd/systemd-measure"
SD_PCREXTEND="/usr/lib/systemd/systemd-pcrextend"
export SYSTEMD_LOG_LEVEL=debug

cryptsetup_has_token_plugin_support() {
    local plugin_path

    plugin_path="$(cryptsetup --help | sed -nr 's/.*LUKS2 external token plugin path: (.*)\./\1/p')/libcryptsetup-token-systemd-tpm2.so)"
    cryptsetup --help | grep -q 'LUKS2 external token plugin support is compiled-in' && [[ -f "$plugin_path" ]]
}

tpm_has_pcr() {
    local algorithm="${1:?}"
    local pcr="${2:?}"

    [[ -f "/sys/class/tpm/tpm0/pcr-$algorithm/$pcr" ]]
}

tpm_check_failure_with_wrong_pin() {
    local testimg="${1:?}"
    local badpin="${2:?}"
    local goodpin="${3:?}"

    # We need to be careful not to trigger DA lockout; allow 2 failures
    tpm2_dictionarylockout -s -n 2
    (! PIN=$badpin systemd-cryptsetup attach test-volume "$testimg" - tpm2-device=auto,headless=1)
    # Verify the correct PIN works, to be sure the failure wasn't a DA lockout
    PIN=$goodpin systemd-cryptsetup attach test-volume "$testimg" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume
    # Clear/reset the DA lockout counter
    tpm2_dictionarylockout -c
}

# Prepare a fresh disk image
img="/tmp/test.img"
truncate -s 20M "$img"
echo -n passphrase >/tmp/passphrase
# Change file mode to avoid "/tmp/passphrase has 0644 mode that is too permissive" messages
chmod 0600 /tmp/passphrase
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$img" /tmp/passphrase

# Unlocking via keyfile
systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto "$img"

# Enroll unlock with default PCR policy
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto "$img"
systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Check with wrong PCR
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1)

# Enroll unlock with PCR+PIN policy
systemd-cryptenroll --wipe-slot=tpm2 "$img"
PASSWORD=passphrase NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=true "$img"
PIN=123456 systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Check failure with wrong PIN; try a few times to make sure we avoid DA lockout
for _ in {0..3}; do
    tpm_check_failure_with_wrong_pin "$img" 123457 123456
done

# Check LUKS2 token plugin unlock (i.e. without specifying tpm2-device=auto)
if cryptsetup_has_token_plugin_support; then
    PIN=123456 systemd-cryptsetup attach test-volume "$img" - headless=1
    systemd-cryptsetup detach test-volume

    # Check failure with wrong PIN
    for _ in {0..3}; do
        tpm_check_failure_with_wrong_pin "$img" 123457 123456
    done
else
    echo 'cryptsetup has no LUKS2 token plugin support, skipping'
fi

# Check failure with wrong PCR (and correct PIN)
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! PIN=123456 systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1)

# Enroll unlock with PCR 0+7
systemd-cryptenroll --wipe-slot=tpm2 "$img"
PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 "$img"
systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
systemd-cryptsetup detach test-volume

# Check with wrong PCR 0
tpm2_pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000
(! systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1)

if tpm_has_pcr sha256 12; then
    # Enroll using an explict PCR value (that does match current PCR value)
    systemd-cryptenroll --wipe-slot=tpm2 "$img"
    EXPECTED_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="12:sha256=$EXPECTED_PCR_VALUE" "$img"
    systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # Same as above plus more PCRs without the value or alg specified
    systemd-cryptenroll --wipe-slot=tpm2 "$img"
    EXPECTED_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="1,12:sha256=$EXPECTED_PCR_VALUE,3" "$img"
    systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # Same as above plus more PCRs with hash alg specified but hash value not specified
    systemd-cryptenroll --wipe-slot=tpm2 "$img"
    EXPECTED_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="1:sha256,12:sha256=$EXPECTED_PCR_VALUE,3" "$img"
    systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    # Now the interesting part, enrolling using a hash value that doesn't match the current PCR value
    systemd-cryptenroll --wipe-slot=tpm2 "$img"
    tpm2_pcrread -Q -o /tmp/pcr.dat sha256:12
    CURRENT_PCR_VALUE=$(cat /sys/class/tpm/tpm0/pcr-sha256/12)
    EXPECTED_PCR_VALUE=$(cat /tmp/pcr.dat /tmp/pcr.dat | openssl dgst -sha256 -r | cut -d ' ' -f 1)
    PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs="12:sha256=$EXPECTED_PCR_VALUE" "$img"
    (! systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1)
    tpm2_pcrextend "12:sha256=$CURRENT_PCR_VALUE"
    systemd-cryptsetup attach test-volume "$img" - tpm2-device=auto,headless=1
    systemd-cryptsetup detach test-volume

    rm -f /tmp/pcr.dat
fi

rm -f "${img:?}"

if [[ -x "$SD_MEASURE" ]]; then
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
else
    echo "$SD_MEASURE not found, skipping PCR policy test case"
fi

if [[ -x "$SD_MEASURE" ]] && tpm_has_pcr sha1 11 && tpm_has_pcr sha256 11; then
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
    truncate -s 20M "$img"
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$img" /tmp/passphrase
    # Ensure that an unrelated signature, when not requested, is not used
    touch /run/systemd/tpm2-pcr-signature.json
    systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto --tpm2-public-key="/tmp/pcrsign-public.pem" "$img"
    # Reset and use the signature now
    rm -f /run/systemd/tpm2-pcr-signature.json
    systemd-cryptenroll --wipe-slot=tpm2 "$img"
    systemd-cryptenroll --unlock-key-file=/tmp/passphrase --tpm2-device=auto --tpm2-public-key="/tmp/pcrsign-public.pem" --tpm2-signature="/tmp/pcrsign.sig2" "$img"

    # Check if we can activate that (without the token module stuff)
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup detach test-volume2

    # Check if we can activate that (and a second time with the token module stuff enabled)
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup detach test-volume2

    # After extending the PCR things should fail
    tpm2_pcrextend 11:sha256=0000000000000000000000000000000000000000000000000000000000000000
    (! SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1)
    (! SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig2",headless=1)

    # But once we sign the current PCRs, we should be able to unlock again
    "$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: >"/tmp/pcrsign.sig3"
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig3",headless=1
    systemd-cryptsetup detach test-volume2
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=1 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig3",headless=1
    systemd-cryptsetup detach test-volume2

    # Test --append mode and de-duplication. With the same parameters signing should not add a new entry
    "$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: --append="/tmp/pcrsign.sig3" >"/tmp/pcrsign.sig4"
    cmp "/tmp/pcrsign.sig3" "/tmp/pcrsign.sig4"

    # Sign one more phase, this should
    "$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=quux:waldo --append="/tmp/pcrsign.sig4" >"/tmp/pcrsign.sig5"
    (! cmp "/tmp/pcrsign.sig4" "/tmp/pcrsign.sig5")

    # Should still be good to unlock, given the old entry still exists
    SYSTEMD_CRYPTSETUP_USE_TOKEN_MODULE=0 systemd-cryptsetup attach test-volume2 "$img" - tpm2-device=auto,tpm2-signature="/tmp/pcrsign.sig5",headless=1
    systemd-cryptsetup detach test-volume2

    # Adding both signatures once more should not change anything, due to the deduplication
    "$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=: --append="/tmp/pcrsign.sig5" >"/tmp/pcrsign.sig6"
    "$SD_MEASURE" sign --current "${MEASURE_BANKS[@]}" --private-key="/tmp/pcrsign-private.pem" --public-key="/tmp/pcrsign-public.pem" --phase=quux:waldo --append="/tmp/pcrsign.sig6" >"/tmp/pcrsign.sig7"
    cmp "/tmp/pcrsign.sig5" "/tmp/pcrsign.sig7"

    rm -f "$img"
else
    echo "$SD_MEASURE or PCR sysfs files not found, skipping signed PCR policy test case"
fi

if [[ -x "$SD_PCREXTEND" ]] && tpm_has_pcr sha256 11 && tpm_has_pcr sha256 15; then
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
    test "$(jq --seq --slurp '.[0].pcr' < /var/log/systemd/tpm2-measure.log)" == "$(printf '\x1e15')"
    test "$(jq --seq --slurp --raw-output '.[0].digests[1].digest' < /var/log/systemd/tpm2-measure.log) *stdin" == "$(echo -n "machine-id:994013bf23864ee7992eab39a96dd3bb" | openssl dgst -hex -sha256 -r)"

    # And similar for the boot phase measurement into PCR 11
    tpm2_pcrread sha256:11 -Q -o /tmp/oldpcr11
    # Do the equivalent of 'SYSTEMD_FORCE_MEASURE=1 "$SD_PCREXTEND" foobar' via Varlink, just to test the Varlink logic (but first we need to patch out the conditionalization...)
    grep -v -e '^Condition' /usr/lib/systemd/system/systemd-pcrextend.socket > /etc/systemd/system/systemd-pcrextend.socket
    systemctl daemon-reload
    systemctl restart systemd-pcrextend.socket
    varlinkctl call /run/systemd/io.systemd.PCRExtend io.systemd.PCRExtend.Extend '{"pcr":11,"text":"foobar"}'
    tpm2_pcrread sha256:11 -Q -o /tmp/newpcr11

    diff /tmp/newpcr11 \
        <(cat /tmp/oldpcr11 <(echo -n "foobar" | openssl dgst -binary -sha256) | openssl dgst -binary -sha256)

    # Check the event log for the 2nd record
    jq --seq --slurp < /var/log/systemd/tpm2-measure.log

    test "$(jq --seq --slurp .[1].pcr < /var/log/systemd/tpm2-measure.log)" == "$(printf '\x1e11')"
    test "$(jq --seq --slurp --raw-output .[1].digests[0].digest < /var/log/systemd/tpm2-measure.log) *stdin" == "$(echo -n "foobar" | openssl dgst -hex -sha256 -r)"

    rm -f /tmp/oldpcr11 /tmp/newpcr11
else
    echo "$SD_PCREXTEND or PCR sysfs files not found, skipping PCR extension test case"
fi

# Ensure that sandboxing doesn't stop creds from being accessible
echo "test" > /tmp/testdata
systemd-creds encrypt /tmp/testdata /tmp/testdata.encrypted --with-key=tpm2
# LoadCredentialEncrypted
systemd-run -p PrivateDevices=yes -p LoadCredentialEncrypted=testdata.encrypted:/tmp/testdata.encrypted --pipe --wait systemd-creds cat testdata.encrypted | cmp - /tmp/testdata
# SetCredentialEncrypted
systemd-run -p PrivateDevices=yes -p SetCredentialEncrypted=testdata.encrypted:"$(cat /tmp/testdata.encrypted)" --pipe --wait systemd-creds cat testdata.encrypted | cmp - /tmp/testdata
rm -f /tmp/testdata

# There is an external issue with libcryptsetup on ppc64 that hits 95% of Ubuntu ppc64 test runs, so skip it
machine="$(uname -m)"
if [ "${machine}" = "ppc64le" ]; then
    touch /testok
    exit 0
fi

cryptenroll_wipe_and_check() {(
    set +o pipefail

    : >/tmp/cryptenroll.out
    systemd-cryptenroll "$@" |& tee /tmp/cryptenroll.out
    grep -qE "Wiped slot [[:digit:]]+" /tmp/cryptenroll.out
)}

img="/tmp/cryptenroll.img"
truncate -s 20M "$img"
echo -n password >/tmp/password
# Change file mode to avoid "/tmp/password has 0644 mode that is too permissive" messages
chmod 0600 /tmp/password
cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$img" /tmp/password

# Enroll additional tokens, keys, and passwords to exercise the list and wipe stuff
systemd-cryptenroll --unlock-key-file=/tmp/password --tpm2-device=auto "$img"
NEWPASSWORD="" systemd-cryptenroll --unlock-key-file=/tmp/password  --password "$img"
NEWPASSWORD=foo systemd-cryptenroll --unlock-key-file=/tmp/password  --password "$img"
for _ in {0..9}; do
    systemd-cryptenroll --unlock-key-file=/tmp/password --recovery-key "$img"
done
PASSWORD="" NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=true "$img"
# Do some basic checks before we start wiping stuff
systemd-cryptenroll "$img"
systemd-cryptenroll "$img" | grep password
systemd-cryptenroll "$img" | grep recovery
# Let's start wiping
cryptenroll_wipe_and_check "$img" --wipe=empty
(! cryptenroll_wipe_and_check "$img" --wipe=empty)
cryptenroll_wipe_and_check "$img" --wipe=empty,0
PASSWORD=foo NEWPASSWORD=foo cryptenroll_wipe_and_check "$img" --wipe=0,0,empty,0,pkcs11,fido2,000,recovery,password --password
systemd-cryptenroll "$img" | grep password
(! systemd-cryptenroll "$img" | grep recovery)
# We shouldn't be able to wipe all keyslots without enrolling a new key first
(! systemd-cryptenroll "$img" --wipe=all)
PASSWORD=foo NEWPASSWORD=foo cryptenroll_wipe_and_check "$img" --password --wipe=all
# Check if the newly (and only) enrolled password works
(! systemd-cryptenroll --unlock-key-file=/tmp/password --recovery-key "$img")
(! PASSWORD="" systemd-cryptenroll --recovery-key "$img")
PASSWORD=foo systemd-cryptenroll --recovery-key "$img"

systemd-cryptenroll --fido2-with-client-pin=false "$img"
systemd-cryptenroll --fido2-with-user-presence=false "$img"
systemd-cryptenroll --fido2-with-user-verification=false "$img"
systemd-cryptenroll --tpm2-pcrs=8 "$img"
systemd-cryptenroll --tpm2-pcrs=boot-loader-code+boot-loader-config "$img"

(! systemd-cryptenroll --fido2-with-client-pin=false)
(! systemd-cryptenroll --fido2-with-user-presence=f "$img" /tmp/foo)
(! systemd-cryptenroll --fido2-with-client-pin=1234 "$img")
(! systemd-cryptenroll --fido2-with-user-presence=1234 "$img")
(! systemd-cryptenroll --fido2-with-user-verification=1234 "$img")
(! systemd-cryptenroll --tpm2-with-pin=1234 "$img")
(! systemd-cryptenroll --recovery-key --password "$img")
(! systemd-cryptenroll --password --recovery-key "$img")
(! systemd-cryptenroll --password --fido2-device=auto "$img")
(! systemd-cryptenroll --password --pkcs11-token-uri=auto "$img")
(! systemd-cryptenroll --password --tpm2-device=auto "$img")
(! systemd-cryptenroll --unlock-fido2-device=auto --unlock-fido2-device=auto "$img")
(! systemd-cryptenroll --unlock-fido2-device=auto --unlock-key-file=/tmp/unlock "$img")
(! systemd-cryptenroll --fido2-credential-algorithm=es512 "$img")
(! systemd-cryptenroll --tpm2-public-key-pcrs=key "$img")
(! systemd-cryptenroll --tpm2-pcrs=key "$img")
(! systemd-cryptenroll --tpm2-pcrs=44+8 "$img")
(! systemd-cryptenroll --tpm2-pcrs=hello "$img")
(! systemd-cryptenroll --wipe-slot "$img")
(! systemd-cryptenroll --wipe-slot=10240000 "$img")
(! systemd-cryptenroll --fido2-device=auto --unlock-fido2-device=auto "$img")

touch /testok
