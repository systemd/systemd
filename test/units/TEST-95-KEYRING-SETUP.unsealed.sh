#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Booted with dm_verity.keyring_unsealed=1: systemd-keyring-setup enrolled the
# certificates from the VOA hierarchy at boot, sealed the keyring, and the
# kernel verifies the signed test image against it.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

if ! grep -E ' keyring +\.dm-verity: ' /proc/keys >/dev/null; then
    echo ".dm-verity keyring not available (kernel < v7.0?), skipping"
    exit 77
fi

[[ "$(systemctl show -P ActiveState systemd-keyring-setup.service)" == "active" ]]
[[ "$(systemctl show -P Result systemd-keyring-setup.service)" == "success" ]]
[[ "$(systemctl show -P ExecMainStatus systemd-keyring-setup.service)" == "0" ]]
[[ "$(cat /sys/module/dm_verity/parameters/keyring_unsealed)" == "Y" ]]

# Sealed, holding the mkosi certificate under its kernel-derived description, the one handed
# over as a credential and the trust anchor
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +08070000 +0 +0 +keyring +\.dm-verity: 3$' /proc/keys
CN="$(openssl x509 -noout -subject -in /usr/share/mkosi.crt | sed 's/^.*CN *= *//')"
grep -E "^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri .*$CN" /proc/keys
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri .*keyring-setup-extra' /proc/keys
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri .*keyring-setup-ca' /proc/keys
# /proc/keys does not show membership, bind them to the keyring
keyctl list %:.dm-verity | grep -F "$CN"
keyctl list %:.dm-verity | grep -F keyring-setup-extra
keyctl list %:.dm-verity | grep -F keyring-setup-ca

# The service enrolled them from the VOA hierarchy in the initrd, before the switch to the host
. /etc/os-release
# Not -u: the initrd run has exited by the time journald reads its messages, so they carry no _SYSTEMD_UNIT=
journalctl --merge -o json -t systemd-keyring-setup >/tmp/keyring-setup.journal.json
enrolled="$(jq -rn --arg m "Enrolled '/usr/share/voa/$ID/image/default/x509/mkosi-certificate.pem' into keyring .dm-verity" \
    'first(inputs | select(.MESSAGE | startswith($m)) | .__MONOTONIC_TIMESTAMP)' /tmp/keyring-setup.journal.json)"
journalctl --merge -o json _PID=1 >/tmp/pid1.journal.json
switched="$(jq -rn 'first(inputs | select(.MESSAGE | startswith("Switching root")) | .__MONOTONIC_TIMESTAMP)' /tmp/pid1.journal.json)"
rm -f /tmp/keyring-setup.journal.json /tmp/pid1.journal.json
[[ -n "$enrolled" && -n "$switched" && "$enrolled" -lt "$switched" ]]
journalctl --merge -o cat -t systemd-keyring-setup |
    grep -E "^Enrolled '/run/voa/[^/]+/image/default/x509/extra-certificate.pem' into keyring .dm-verity" >/dev/null
journalctl --merge -o cat -t systemd-keyring-setup |
    grep -F "Enrolled '/usr/share/voa/$ID/trust-anchor-image/default/x509/ca-certificate.pem' into keyring .dm-verity" >/dev/null

# Only certificates signed by an enrolled key can be added anymore, the mask and the restriction are
# frozen, not even for root
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=stranger -days 1 \
    -keyout /dev/null -out /tmp/stranger.pem
openssl x509 -in /tmp/stranger.pem -outform DER -out /tmp/stranger.der
(! keyctl padd asymmetric '' %:.dm-verity </tmp/stranger.der)
(! keyctl restrict_keyring %:.dm-verity)
(! keyctl invalidate %:.dm-verity)
(! keyctl setperm %:.dm-verity 0x3f3f0000)
keyctl list %:.dm-verity
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=chained \
    -keyout /dev/null -out /tmp/chained.csr
openssl x509 -req -in /tmp/chained.csr -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
    -set_serial 1 -days 1 -extfile <(echo authorityKeyIdentifier=keyid,issuer) -out /tmp/chained.pem
openssl x509 -in /tmp/chained.pem -outform DER | keyctl padd asymmetric '' %:.dm-verity
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 4$' /proc/keys

# A later stage finds the keyring provisioned and exits successfully without enrolling anything twice
"$KEYRING_SETUP" .dm-verity
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 4$' /proc/keys

# A certificate configured after the fact is refused and reported as bad input unless it is signed
# by an enrolled key
mkdir -p "/etc/voa/$ID/image/default/x509"
cp /tmp/stranger.pem "/etc/voa/$ID/image/default/x509/late-certificate.pem"
rc=0
"$KEYRING_SETUP" .dm-verity || rc=$?
[[ "$rc" -eq 65 ]]
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 4$' /proc/keys
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=late \
    -keyout /dev/null -out /tmp/late.csr
openssl x509 -req -in /tmp/late.csr -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
    -set_serial 2 -days 1 -extfile <(echo authorityKeyIdentifier=keyid,issuer) \
    -out "/etc/voa/$ID/image/default/x509/late-certificate.pem"
"$KEYRING_SETUP" .dm-verity
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 5$' /proc/keys
grep -E "^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri +late: [0-9a-f]+: " /proc/keys
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
