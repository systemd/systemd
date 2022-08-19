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
if cryptsetup --help | grep -q 'LUKS2 external token plugin support is compiled-in'; then
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

if [[ -e /usr/lib/systemd/systemd-measure ]]; then
    echo HALLO > /tmp/tpmdata1
    echo foobar > /tmp/tpmdata2

    cat >/tmp/result <<EOF
11:sha1=5177e4ad69db92192c10e5f80402bf81bfec8a81
11:sha256=37b48bd0b222394dbe3cceff2fca4660c4b0a90ae9369ec90b42f14489989c13
11:sha384=5573f9b2caf55b1d0a6a701f890662d682af961899f0419cf1e2d5ea4a6a68c1f25bd4f5b8a0865eeee82af90f5cb087
11:sha512=961305d7e9981d6606d1ce97b3a9a1f92610cac033e9c39064895f0e306abc1680463d55767bd98e751eae115bdef3675a9ee1d29ed37da7885b1db45bb2555b
EOF

    /usr/lib/systemd/systemd-measure calculate --linux=/tmp/tpmdata1 --initrd=/tmp/tpmdata2 --bank=sha1 --bank=sha256 --bank=sha384 --bank=sha512 | cmp - /tmp/result
else
    echo "/usr/lib/systemd/systemd-measure not found, skipping the test case"
fi

echo OK >/testok

exit 0
