# SPDX-License-Identifier: MIT-0

# Enroll the TPM2 security chip in the LUKS2 volume, and bind it to PCR 7
# only. Replace /dev/sdXn by the partition to use (e.g. /dev/sda1).
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/sdXn

# Test: Let's run systemd-cryptsetup to test if this worked.
sudo /usr/lib/systemd/systemd-cryptsetup attach mytest /dev/sdXn - tpm2-device=auto

# If that worked, let's now add the same line persistently to /etc/crypttab,
# for the future.
sudo bash -c 'echo "mytest /dev/sdXn - tpm2-device=auto" >> /etc/crypttab'
