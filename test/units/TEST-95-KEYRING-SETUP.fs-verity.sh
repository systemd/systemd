#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# The kernel never seals .fs-verity: systemd-keyring-setup enrolled the
# certificate from the VOA hierarchy at boot and sealed and locked down the
# keyring like the others, so nothing can be added later, not even via a
# credential.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

if ! grep -E ' keyring +\.fs-verity: ' /proc/keys >/dev/null; then
    echo ".fs-verity keyring not available (CONFIG_FS_VERITY_BUILTIN_SIGNATURES?), skipping"
    exit 77
fi

[[ "$(systemctl show -P ActiveState systemd-keyring-setup.service)" == "active" ]]
[[ "$(systemctl show -P Result systemd-keyring-setup.service)" == "success" ]]

# Locked down, holding the mkosi certificate
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +08010000 +0 +0 +keyring +\.fs-verity: 1$' /proc/keys
(! openssl x509 -in /usr/share/mkosi.crt -outform DER | keyctl padd asymmetric '' %:.fs-verity)
(! keyctl list %:.fs-verity)

# A certificate handed over later is placed into the hierarchy, but cannot be
# enrolled anymore, and that is not an error
systemd-run --pipe --wait \
    --property LoadCredential=keyring-setup.fs-verity.late:/usr/share/mkosi.crt \
    "$KEYRING_SETUP" .fs-verity
ls /run/voa/*/fs-verity/default/x509/late-certificate.pem
grep -E ' +08010000 +0 +0 +keyring +\.fs-verity: 1$' /proc/keys
