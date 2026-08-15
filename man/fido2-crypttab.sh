# SPDX-License-Identifier: MIT-0

# Enroll the security token in the LUKS2 volume. Replace /dev/sdXn by the
# partition to use (e.g. /dev/sda1).
sudo systemd-cryptenroll --fido2-device=auto /dev/sdXn

# Test: Let's run systemd-cryptsetup to test if this worked.
sudo systemd-cryptsetup attach mytest /dev/sdXn none fido2-device=auto

# If that worked, let's now add the same line persistently to /etc/crypttab,
# for the future. We do not want to use the (unstable) /dev/sdX name, so let's
# figure out a stable link:
udevadm info -q symlink -r /dev/sdXn

# Now add the line using the by-uuid symlink to /etc/crypttab:
sudo bash -c 'echo "mytest /dev/disk/by-uuid/... none fido2-device=auto" >>/etc/crypttab'

# Depending on your distribution and encryption setup, you may need to manually
# regenerate your initramfs to be able to use a FIDO2 device to unlock the
# partition during early boot.
# More information at https://unix.stackexchange.com/a/705809.
# On Fedora based systems:
sudo dracut --force
# On Debian based systems:
sudo update-initramfs -u
