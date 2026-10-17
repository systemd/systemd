#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Booted without dm_verity.keyring_unsealed=1: the kernel sealed .dm-verity
# empty, systemd-keyring-setup finds the certificates but can enroll nothing,
# and must leave the keyring alone.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

# Everything up to the keyring gate below needs no kernel keyring support
[[ "$(systemctl show -P ActiveState systemd-keyring-setup.service)" == "active" ]]
[[ "$(systemctl show -P Result systemd-keyring-setup.service)" == "success" ]]
[[ "$(systemctl show -P ExecMainStatus systemd-keyring-setup.service)" == "0" ]]

# An unknown keyring, a name without its leading dot, and --json= without --dry-run are rejected
(! "$KEYRING_SETUP" --dry-run .bogus)
(! "$KEYRING_SETUP" --dry-run dm-verity)
(! "$KEYRING_SETUP" --json=short .dm-verity)

# The usage check keeps a certificate that cannot sign code out and reports it as bad input, while
# one permitting any usage and a CA certificate placed among the trust anchors are accepted
. /etc/os-release
mkdir -p "/etc/voa/$ID/kernel-keyring/dm-verity/x509" "/etc/voa/$ID/trust-anchor-kernel-keyring/dm-verity/x509"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=tls -days 1 \
    -addext extendedKeyUsage=serverAuth \
    -keyout /dev/null -out "/etc/voa/$ID/kernel-keyring/dm-verity/x509/tls-certificate.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=anyeku -days 1 \
    -addext extendedKeyUsage=critical,anyExtendedKeyUsage \
    -keyout /dev/null -out "/etc/voa/$ID/kernel-keyring/dm-verity/x509/anyeku-certificate.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=ca -days 1 \
    -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign \
    -keyout /dev/null -out "/etc/voa/$ID/trust-anchor-kernel-keyring/dm-verity/x509/ca-certificate.pem"
: > "/etc/voa/$ID/kernel-keyring/dm-verity/x509/empty-certificate.pem"
truncate -s 2M "/etc/voa/$ID/kernel-keyring/dm-verity/x509/large-certificate.pem"
rc=0
"$KEYRING_SETUP" --dry-run --no-pager --json=short .dm-verity >/tmp/keyring-setup.json || rc=$?
[[ "$rc" -eq 65 ]]
jq -e '.[0].certificates | any(endswith("/mkosi-certificate.pem")) and any(endswith("/anyeku-certificate.pem"))
    and any(endswith("/trust-anchor-kernel-keyring/dm-verity/x509/ca-certificate.pem"))
    and (any(endswith("/tls-certificate.pem")) | not)
    and (any(endswith("/empty-certificate.pem")) | not)
    and (any(endswith("/large-certificate.pem")) | not)' /tmp/keyring-setup.json

# The .bpf spec looks up the bpf role
mkdir -p "/etc/voa/$ID/kernel-keyring/bpf/x509"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=bpfrole -days 1 \
    -keyout /dev/null -out "/etc/voa/$ID/kernel-keyring/bpf/x509/bpfrole-certificate.pem"
"$KEYRING_SETUP" --dry-run --no-pager --json=short .bpf >/tmp/keyring-setup-bpf.json
jq -e '.[0].certificates | any(endswith("/kernel-keyring/bpf/x509/bpfrole-certificate.pem"))' /tmp/keyring-setup-bpf.json
# .fs-verity has no keyring_unsealed parameter, its kernel_unsealed state is null
"$KEYRING_SETUP" --dry-run --no-pager --json=short .fs-verity | jq -e '.[0].kernel_unsealed == null'
rm -rf "/etc/voa/$ID" /tmp/keyring-setup.json /tmp/keyring-setup-bpf.json

if ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
    if ! modprobe dm_verity 2>/dev/null || ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
        echo ".dm-verity keyring not available (kernel < v7.0?), skipping"
        exit 77
    fi
    # The service loads dm_verity itself, the keyring must have existed when it ran
    echo "ERROR: dm_verity was not loaded when systemd-keyring-setup.service ran" >&2
    exit 1
fi

[[ "$(cat /sys/module/dm_verity/parameters/keyring_unsealed)" == "N" ]]

# The initial permission mask is untouched and the keyring stays empty
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +082f0000 +0 +0 +keyring +\.dm-verity: empty$' /proc/keys

# The certificates were found, mkosi.crt among them
"$KEYRING_SETUP" --dry-run --no-pager --json=short .dm-verity |
    jq -e '.[0] | .exists == true and .kernel_unsealed == false and .sealed == false and (.certificates | any(endswith("/mkosi-certificate.pem")))'

# Running again changes nothing
"$KEYRING_SETUP" .dm-verity
grep -E ' +082f0000 +0 +0 +keyring +\.dm-verity: empty$' /proc/keys

# Without a key in the .dm-verity keyring the kernel cannot verify the signed
# test image, so with systemd's userspace fallback masked the activation must
# fail, and succeed once the fallback is available again.
mkdir -p /etc/verity.d
ln -sf /dev/null /etc/verity.d/mkosi.crt
(! systemd-run --pipe --wait \
    --property RootImage=/usr/share/minimal_0.raw \
    --property RootImagePolicy=root=signed \
    bash --version >/dev/null)
rm -f /etc/verity.d/mkosi.crt
systemd-run --pipe --wait \
    --property RootImage=/usr/share/minimal_0.raw \
    --property RootImagePolicy=root=signed \
    bash --version >/dev/null
