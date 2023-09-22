# SPDX-License-Identifier: MIT-0

# Enroll the TPM2 security chip in the LUKS2 volume, and bind it to PCR 7
# only. Replace /dev/sdXn by the partition to use (e.g. /dev/sda1).
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/sdXn

# Test: Let's run systemd-cryptsetup to test if this worked.
sudo /usr/lib/systemd/systemd-cryptsetup attach mytest /dev/sdXn - tpm2-device=auto

# If that worked, let's now add the same line persistently to /etc/crypttab,
# for the future. We don't want to use the (unstable) /dev/sdX name, so let's
# figure out a stable link:
udevadm info --query=property --property=DEVLINKS /dev/sdXn

# Now add the line using the by-uuid symlink to /etc/crypttab:
sudo bash -c 'echo "mytest /dev/disk/by-uuid/... - tpm2-device=auto" >>/etc/crypttab'

# Depending on your distribution and encryption setup, you may need to manually
# regenerate your initramfs to be able to use a TPM2 security chip to unlock
# the partition during early boot.
# More information at https://unix.stackexchange.com/a/705809.
# On Fedora based systems:
sudo dracut --force
# On Debian based systems:
sudo update-initramfs -u
