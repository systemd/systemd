#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The .fs-verity keyring is never sealed by the kernel: empty at boot it is
# left open, and once a certificate reaches it — here via a credential — it is
# sealed and locked down.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

if ! grep -E ' keyring +\.fs-verity: ' /proc/keys >/dev/null; then
    echo ".fs-verity keyring not available (CONFIG_FS_VERITY_BUILTIN_SIGNATURES?), skipping"
    exit 77
fi

grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +082f0000 +0 +0 +keyring +\.fs-verity: empty$' /proc/keys

. /etc/os-release
systemd-run --pipe --wait \
    --property LoadCredential=keyring-setup.fs-verity.mkosi:/usr/share/mkosi.crt \
    "$KEYRING_SETUP" .fs-verity
test -f "/run/voa/$ID/fs-verity/default/x509/mkosi-certificate.pem"

grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +08010000 +0 +0 +keyring +\.fs-verity: 1$' /proc/keys
(! openssl x509 -in /usr/share/mkosi.crt -outform DER | keyctl padd asymmetric '' %:.fs-verity)
(! keyctl list %:.fs-verity)

# Running again finds it provisioned
"$KEYRING_SETUP" .fs-verity
