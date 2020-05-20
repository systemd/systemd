# Make sure no one can read the files we generate but us
umask 077

# Destroy any old key on the Yubikey (careful!)
ykman piv reset

# Generate a new private/public key pair on the device, store the public key in 'pubkey.pem'.
ykman piv generate-key -a RSA2048 9d pubkey.pem

# Create a self-signed certificate from this public key, and store it on the
# device. The "subject" should be an arbitrary string to identify the token in
# the p11tool output below.
ykman piv generate-certificate --subject "Knobelei" 9d pubkey.pem

# Check if the newly create key on the Yubikey shows up as token in PKCS#11. Have a look at the output, and
# copy the resulting token URI to the clipboard.
p11tool --list-tokens

# Generate a (secret) random key to use as LUKS decryption key.
dd if=/dev/urandom of=plaintext.bin bs=128 count=1

# Encode the secret key also as base64 text (with all whitespace removed)
base64 < plaintext.bin | tr -d '\n\r\t ' > plaintext.base64

# Encrypt this newly generated (binary) LUKS decryption key using the public key whose private key is on the
# Yubikey, store the result in /etc/cryptsetup-keys.d/mytest.key, where we'll look for it during boot.
mkdir -p /etc/cryptsetup-keys.d
sudo openssl rsautl -encrypt -pubin -inkey pubkey.pem -in plaintext.bin -out /etc/cryptsetup-keys.d/mytest.key

# Configure the LUKS decryption key on the LUKS device. We use very low pbkdf settings since the key already
# has quite a high quality (it comes directly from /dev/urandom after all), and thus we don't need to do much
# key derivation. Replace /dev/sdXn by the partition to use (e.g. sda1)
sudo cryptsetup luksAddKey /dev/sdXn plaintext.base64 --pbkdf=pbkdf2 --pbkdf-force-iterations=1000

# Now securely delete the plain text LUKS key, we don't need it anymore, and since it contains secret key
# material it should be removed from disk thoroughly.
shred -u plaintext.bin plaintext.base64

# We don't need the public key anymore either, let's remove it too. Since this one is not security
# sensitive we just do a regular "rm" here.
rm pubkey.pem

# Test: Let's run systemd-cryptsetup to test if this all worked. The option string should contain the full
# PKCS#11 URI we have in the clipboard; it tells the tool how to decipher the encrypted LUKS key. Note that
# systemd-cryptsetup automatically searches for the encrypted key in /etc/cryptsetup-keys.d/, hence we do
# not need to specify the key file path explicitly here.
sudo systemd-cryptsetup attach mytest /dev/sdXn - 'pkcs11-uri=pkcs11:…'

# If that worked, let's now add the same line persistently to /etc/crypttab, for the future.
sudo bash -c 'echo "mytest /dev/sdXn - \'pkcs11-uri=pkcs11:…\'" >> /etc/crypttab'
