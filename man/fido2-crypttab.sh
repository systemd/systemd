# SPDX-License-Identifier: MIT-0

# Enroll the security token in the LUKS2 volume. Replace /dev/sdXn by the
# partition to use (e.g. /dev/sda1).
sudo systemd-cryptenroll --fido2-device=auto /dev/sdXn

# Test: Let's run systemd-cryptsetup to test if this worked.
sudo /usr/lib/systemd/systemd-cryptsetup attach mytest /dev/sdXn - fido2-device=auto

# If that worked, let's now add the same line persistently to /etc/crypttab,
# for the future.
sudo bash -c 'echo "mytest /dev/sdXn - fido2-device=auto" >>/etc/crypttab'

# Depending on your distribution you may need to manually regenerate your initramfs 
# to be able to use a FIDO2-Device to unlock the partition at boot. (https://unix.stackexchange.com/a/705809)
# On Fedora based systems:
sudo dracut --regenerate-all --force
# On Debian based systems:
sudo update-initramfs -u
