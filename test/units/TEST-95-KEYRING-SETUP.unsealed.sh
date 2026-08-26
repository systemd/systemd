#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Booted with dm_verity.keyring_unsealed=1: systemd-keyring-setup enrolled the
# certificates from the VOA hierarchy at boot, sealed and locked down the
# keyring, and the kernel verifies the signed test image against it.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

if ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
    echo ".dm-verity keyring not available (kernel < v7.0?), skipping"
    exit 77
fi

[[ "$(systemctl show -P ActiveState systemd-keyring-setup.service)" == "active" ]]
[[ "$(systemctl show -P Result systemd-keyring-setup.service)" == "success" ]]
[[ "$(cat /sys/module/dm_verity/parameters/keyring_unsealed)" == "Y" ]]

# Locked down, holding the mkosi certificate under its kernel-derived description
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +08010000 +0 +0 +keyring +\.dm-verity: [0-9]+$' /proc/keys
CN="$(openssl x509 -noout -subject -in /usr/share/mkosi.crt | sed 's/^.*CN *= *//')"
grep -E "^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri .*$CN" /proc/keys

# Nothing can be added, removed, listed, or unlocked anymore, not even by root
(! openssl x509 -in /usr/share/mkosi.crt -outform DER | keyctl padd asymmetric '' %:.dm-verity)
(! keyctl restrict_keyring %:.dm-verity)
(! keyctl clear %:.dm-verity)
(! keyctl list %:.dm-verity)
(! keyctl revoke %:.dm-verity)
(! keyctl invalidate %:.dm-verity)
(! keyctl setperm %:.dm-verity 0x3f3f0000)
grep -E ' +08010000 +0 +0 +keyring +\.dm-verity: [0-9]+$' /proc/keys

# A later stage finds the keyring provisioned and exits successfully
"$KEYRING_SETUP" .dm-verity

# A certificate configured after the fact cannot be enrolled anymore, and that is not an error
. /etc/os-release
mkdir -p "/etc/voa/$ID/image/default/x509"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=late -days 1 \
    -keyout /dev/null -out "/etc/voa/$ID/image/default/x509/late-certificate.pem"
"$KEYRING_SETUP" .dm-verity
grep -E ' +08010000 +0 +0 +keyring +\.dm-verity: 1$' /proc/keys
rm -rf "/etc/voa/$ID"

# The kernel path is what authenticates the image: mask the certificate for
# systemd's userspace fallback and require a signed image, the activation then
# only succeeds if the kernel accepted the signature via the .dm-verity keyring.
mkdir -p /etc/verity.d
ln -sf /dev/null /etc/verity.d/mkosi.crt
systemd-run --pipe --wait \
    --property RootImage=/usr/share/minimal_0.raw \
    --property RootImagePolicy=root=signed \
    bash --version >/dev/null
rm -f /etc/verity.d/mkosi.crt
