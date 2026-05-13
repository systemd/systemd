# SPDX-License-Identifier: MIT-0

# Enroll the TPM2 security chip in the LUKS2 volume, and bind it to PCR 7
# only. Replace /dev/sdXn by the partition to use (e.g. /dev/sda1).
sudo systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7 /dev/sdXn

# Test: Let's run systemd-cryptsetup to test if this worked.
sudo systemd-cryptsetup attach mytest /dev/sdXn none tpm2-device=auto

# If that worked, let's now add the same line persistently to /etc/crypttab,
# for the future. We do not want to use the (unstable) /dev/sdX name, so let's
# figure out a stable link:
udevadm info -q symlink -r /dev/sdXn

# Now add the line using the by-uuid symlink to /etc/crypttab:
sudo bash -c 'echo "mytest /dev/disk/by-uuid/... none tpm2-device=auto" >>/etc/crypttab'

# And now let's check that automatic unlocking works:
sudo systemd-cryptsetup detach mytest
sudo systemctl daemon-reload
sudo systemctl start cryptsetup.target
systemctl is-active systemd-cryptsetup@mytest.service

# Once we have the device which will be unlocked automatically, we can use it.
# Usually we would create a file system and add it to /etc/fstab:
sudo mkfs.ext4 /dev/mapper/mytest
# This prints a 'Filesystem UUID', which we can use as a stable name:
sudo bash -c 'echo "/dev/disk/by-uuid/... /var/mytest ext4 defaults,x-systemd.mkdir 0 2" >>/etc/fstab'
# And now let's check that the mounting works:
sudo systemctl daemon-reload
sudo systemctl start /var/mytest
systemctl status /var/mytest

# Depending on your distribution and encryption setup, you may need to manually
# regenerate your initramfs to be able to use a TPM2 security chip to unlock
# the partition during early boot.
# More information at https://unix.stackexchange.com/a/705809.
# On Fedora based systems:
sudo dracut --force
# On Debian based systems:
sudo update-initramfs -u
