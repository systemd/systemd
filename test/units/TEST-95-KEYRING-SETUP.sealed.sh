#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Booted without dm_verity.keyring_unsealed=1: the kernel sealed .dm-verity
# empty, systemd-keyring-setup finds the certificates but can enroll nothing,
# and must leave the keyring alone.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

if ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
    modprobe dm_verity 2>/dev/null || true
fi
if ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
    echo ".dm-verity keyring not available (kernel < v7.0?), skipping"
    exit 77
fi

[[ "$(systemctl show -P ActiveState systemd-keyring-setup.service)" == "active" ]]
[[ "$(systemctl show -P Result systemd-keyring-setup.service)" == "success" ]]
[[ "$(cat /sys/module/dm_verity/parameters/keyring_unsealed)" == "N" ]]

# The initial permission mask is untouched and the keyring stays empty
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +082f0000 +0 +0 +keyring +\.dm-verity: empty$' /proc/keys

# The certificates were found, mkosi.crt among them
"$KEYRING_SETUP" --dry-run --no-pager --json=short .dm-verity |
    jq -e '.[0] | .exists == true and .unsealed == "no" and .locked == false and (.certificates | any(endswith("/mkosi-certificate.pem")))'

# Running again changes nothing
"$KEYRING_SETUP" .dm-verity
grep -E ' +082f0000 +0 +0 +keyring +\.dm-verity: empty$' /proc/keys
