# SPDX-License-Identifier: MIT-0

# Destroy any old key on the Yubikey (careful!)
ykman piv reset

# Generate a new private/public key pair on the device, store the public key in
# 'pubkey.pem'.
ykman piv generate-key -a RSA2048 9d pubkey.pem

# Create a self-signed certificate from this public key, and store it on the
# device. The "subject" should be an arbitrary user-chosen string to identify
# the token with.
ykman piv generate-certificate --subject "Knobelei" 9d pubkey.pem

# We don't need the public key anymore, let's remove it. Since it is not
# security sensitive we just do a regular "rm" here.
rm pubkey.pem

# Enroll the freshly initialized security token in the LUKS2 volume. Replace
# /dev/sdXn by the partition to use (e.g. /dev/sda1).
sudo systemd-cryptenroll --pkcs11-token-uri=auto /dev/sdXn

# Test: Let's run systemd-cryptsetup to test if this all worked.
sudo /usr/lib/systemd/systemd-cryptsetup attach mytest /dev/sdXn - pkcs11-uri=auto

# If that worked, let's now add the same line persistently to /etc/crypttab,
# for the future.
sudo bash -c 'echo "mytest /dev/sdXn - pkcs11-uri=auto" >> /etc/crypttab'
