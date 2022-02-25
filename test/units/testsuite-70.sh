#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -ex
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

# Prepare fresh disk image
dd if=/dev/zero of=/test.img bs=1024k count=100 status=none
echo -n passphrase >/tmp/passphrase
cryptsetup luksFormat -q --use-urandom test.img /tmp/passphrase

# Enroll unlock with default PCR policy
env PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto /test.img
/usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1
cryptsetup luksClose test-volume

# Check with wrong PCR
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
/usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1 && exit 1

# Enroll unlock with PCR+PIN policy
systemd-cryptenroll --wipe-slot=tpm2 /test.img
env PASSWORD=passphrase NEWPIN=123456 systemd-cryptenroll --tpm2-device=auto --tpm2-with-pin=true /test.img
env PIN=123456 /usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1
cryptsetup luksClose test-volume

# Check failure with wrong PIN
env PIN=123457 /usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1 && exit 1

# Check failure with wrong PCR (and correct PIN)
tpm2_pcrextend 7:sha256=0000000000000000000000000000000000000000000000000000000000000000
env PIN=123456 /usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1 && exit 1

# Enroll unlock with PCR 0+7
systemd-cryptenroll --wipe-slot=tpm2 /test.img
env PASSWORD=passphrase systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=0+7 /test.img
/usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1
cryptsetup luksClose test-volume

# Check with wrong PCR 0
tpm2_pcrextend 0:sha256=0000000000000000000000000000000000000000000000000000000000000000
/usr/lib/systemd/systemd-cryptsetup attach test-volume /test.img - tpm2-device=auto,headless=1 && exit 1

echo OK >/testok

exit 0
