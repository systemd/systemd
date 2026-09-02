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
"$KEYRING_SETUP" --dry-run --no-pager --json=short .dm-verity | jq -e '.[0].unsealed == true'

# The service enrolled them from the VOA hierarchy in the initrd, before the switch to the host
. /etc/os-release
# Not -u: the initrd run has exited by the time journald reads its messages, so they carry no _SYSTEMD_UNIT=
journalctl --merge -o json -t systemd-keyring-setup >/tmp/keyring-setup.journal.json
enrolled="$(jq -rn --arg m "Enrolled '/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/mkosi-certificate.pem' into keyring .dm-verity" \
    'first(inputs | select(.MESSAGE | startswith($m)) | .__MONOTONIC_TIMESTAMP)' /tmp/keyring-setup.journal.json)"
journalctl --merge -o json _PID=1 >/tmp/pid1.journal.json
switched="$(jq -rn 'first(inputs | select(.MESSAGE | startswith("Switching root")) | .__MONOTONIC_TIMESTAMP)' /tmp/pid1.journal.json)"
rm -f /tmp/keyring-setup.journal.json /tmp/pid1.journal.json
[[ -n "$enrolled" && -n "$switched" && "$enrolled" -lt "$switched" ]]
journalctl --merge -o cat -t systemd-keyring-setup |
    grep -E "^Enrolled '/run/voa/[^/]+/kernel-keyring/dm-verity/x509/extra-certificate.pem' into keyring .dm-verity" >/dev/null
journalctl --merge -o cat -t systemd-keyring-setup |
    grep -F "Enrolled '/usr/share/voa/$ID/trust-anchor-kernel-keyring/dm-verity/x509/ca-certificate.pem' into keyring .dm-verity" >/dev/null

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
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-again.log
(! grep -F "Enrolled '" /tmp/keyring-setup-again.log >/dev/null)
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 4$' /proc/keys

# A certificate configured after the fact is refused and reported as bad input unless it is signed
# by an enrolled key
mkdir -p "/etc/voa/$ID/kernel-keyring/dm-verity/x509"
cp /tmp/stranger.pem "/etc/voa/$ID/kernel-keyring/dm-verity/x509/late-certificate.pem"
rc=0
"$KEYRING_SETUP" .dm-verity || rc=$?
[[ "$rc" -eq 65 ]]
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 4$' /proc/keys
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=late \
    -keyout /dev/null -out /tmp/late.csr
openssl x509 -req -in /tmp/late.csr -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
    -set_serial 2 -days 1 -extfile <(echo authorityKeyIdentifier=keyid,issuer) \
    -out "/etc/voa/$ID/kernel-keyring/dm-verity/x509/late-certificate.pem"
"$KEYRING_SETUP" .dm-verity
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 5$' /proc/keys
grep -E "^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri +late: [0-9a-f]+: " /proc/keys

# On a colliding subject and key identifier the copy from the highest-priority load path wins
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=dup \
    -keyout /tmp/dup.key -out /tmp/dup.csr
openssl x509 -req -in /tmp/dup.csr -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
    -set_serial 3 -days 1 -extfile <(echo authorityKeyIdentifier=keyid,issuer) \
    -out "/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/dup-certificate.pem"
openssl x509 -req -in /tmp/dup.csr -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
    -set_serial 4 -days 2 -extfile <(echo authorityKeyIdentifier=keyid,issuer) \
    -out "/etc/voa/$ID/kernel-keyring/dm-verity/x509/dup-certificate.pem"
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-dup.log
grep -F "Enrolled '/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/dup-certificate.pem'" /tmp/keyring-setup-dup.log >/dev/null
grep -F "Enrolled '/etc/voa/$ID/kernel-keyring/dm-verity/x509/dup-certificate.pem'" /tmp/keyring-setup-dup.log >/dev/null
grep -F "'/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/dup-certificate.pem' was superseded by a certificate of higher priority" /tmp/keyring-setup-dup.log >/dev/null
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 6$' /proc/keys
rm -f "/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/dup-certificate.pem"

# The byte-identical certificate in two load paths is one candidate, not a supersede
cp "/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/mkosi-certificate.pem" \
   "/etc/voa/$ID/kernel-keyring/dm-verity/x509/mkosi-certificate.pem"
SYSTEMD_LOG_LEVEL=debug "$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-samecert.log
grep -F "'/usr/share/voa/$ID/kernel-keyring/dm-verity/x509/mkosi-certificate.pem' is identical to '/etc/voa/$ID/kernel-keyring/dm-verity/x509/mkosi-certificate.pem', skipping." /tmp/keyring-setup-samecert.log >/dev/null
(! grep -F "Enrolled '" /tmp/keyring-setup-samecert.log >/dev/null)
(! grep -F "was superseded" /tmp/keyring-setup-samecert.log >/dev/null)
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 6$' /proc/keys
rm -f "/etc/voa/$ID/kernel-keyring/dm-verity/x509/mkosi-certificate.pem"

# Without a subject key identifier the serial number, DER padding included, identifies the key:
# CN=noskid, serial 0x8112131415161718, no extensions, signed by the committed keyring-setup-ca key,
# minted by mkosi/keyring-setup-ca.py
cat > "/etc/voa/$ID/kernel-keyring/dm-verity/x509/noskid-certificate.pem" <<'CERT'
-----BEGIN CERTIFICATE-----
MIIBIjCByaADAgECAgkAgRITFBUWFxgwCgYIKoZIzj0EAwIwGzEZMBcGA1UEAwwQ
a2V5cmluZy1zZXR1cC1jYTAgFw0yNjA5MDExOTI0MzZaGA8yMTI2MDgwODE5MjQz
NlowETEPMA0GA1UEAwwGbm9za2lkMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
FRpKLUgmHK8vFB9/N5ZRV54Bwk8uOxU8tt1R1A3OMwgn/ct32PBBNj5HbiS/Wta2
qs6KODUBlPVfCEXktGHMYzAKBggqhkjOPQQDAgNIADBFAiEAsd92t7WgIFHe+cp/
1gjd7OXQw+wkW+Y33iixvkGLA/QCIBLVHP7dhYYkqkxZSkrcUQF805lE893LDnuF
MQVSUlGj
-----END CERTIFICATE-----
CERT
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-noskid.log
grep -F "Enrolled '/etc/voa/$ID/kernel-keyring/dm-verity/x509/noskid-certificate.pem' into keyring .dm-verity as noskid: 008112131415161718" /tmp/keyring-setup-noskid.log >/dev/null
keyctl list %:.dm-verity | grep -F 'noskid: 008112131415161718'
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 7$' /proc/keys

# And the second run recognizes it by that identifier and enrolls nothing
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-noskid2.log
(! grep -F "Enrolled '/etc/voa/$ID/kernel-keyring/dm-verity/x509/noskid-certificate.pem'" /tmp/keyring-setup-noskid2.log >/dev/null)
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 7$' /proc/keys

# A serial without the top bit set gets no zero pad: CN=noskid2, serial 0x11121314, same CA and script
cat > "/etc/voa/$ID/kernel-keyring/dm-verity/x509/noskid2-certificate.pem" <<'CERT'
-----BEGIN CERTIFICATE-----
MIIBHjCBxaADAgECAgQREhMUMAoGCCqGSM49BAMCMBsxGTAXBgNVBAMMEGtleXJp
bmctc2V0dXAtY2EwIBcNMjYwOTAxMTkyNDM2WhgPMjEyNjA4MDgxOTI0MzZaMBIx
EDAOBgNVBAMMB25vc2tpZDIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQZeGsy
lGeEJ5rQtap+PKYtjPtqc3j84NM++obHFcfMjt+jhTRUUtoZxP7cYvODHLZiJqne
y5VXUwcozNcN7E3EMAoGCCqGSM49BAMCA0gAMEUCIQCjnDs9G6zA1fNGMhIRSnHV
f0WXbXciDE8wxo/p7owp7wIgGMLuK/KOyRkgKZLNZx9HG38xmgZYb73tcGFeqg2X
ihY=
-----END CERTIFICATE-----
CERT
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-noskid3.log
grep -F "Enrolled '/etc/voa/$ID/kernel-keyring/dm-verity/x509/noskid2-certificate.pem' into keyring .dm-verity as noskid2: 11121314" /tmp/keyring-setup-noskid3.log >/dev/null
keyctl list %:.dm-verity | grep -F 'noskid2: 11121314'
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 8$' /proc/keys

# Key material writable by others is refused, once the mode is sane it is enrolled
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=loose \
    -keyout /dev/null -out /tmp/loose.csr
openssl x509 -req -in /tmp/loose.csr -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
    -set_serial 5 -days 1 -extfile <(echo authorityKeyIdentifier=keyid,issuer) \
    -out "/etc/voa/$ID/kernel-keyring/dm-verity/x509/loose-certificate.pem"
chmod 0666 "/etc/voa/$ID/kernel-keyring/dm-verity/x509/loose-certificate.pem"
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-loose.log
grep -F "Ignoring '/etc/voa/$ID/kernel-keyring/dm-verity/x509/loose-certificate.pem': writable by group or others." /tmp/keyring-setup-loose.log >/dev/null
(! keyctl list %:.dm-verity | grep -F 'loose' >/dev/null)
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 8$' /proc/keys
chmod 0644 "/etc/voa/$ID/kernel-keyring/dm-verity/x509/loose-certificate.pem"
"$KEYRING_SETUP" .dm-verity
keyctl list %:.dm-verity | grep -F 'loose'
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 9$' /proc/keys

# A file holding more than one certificate is refused as a whole, intermediates cannot be smuggled in
for cn in chainfirst chainsecond; do
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=$cn" \
        -keyout /dev/null -out "/tmp/$cn.csr"
    openssl x509 -req -in "/tmp/$cn.csr" -CA /usr/share/mkosi.crt -CAkey /usr/share/mkosi.key \
        -set_serial "0x$(printf '%s' "$cn" | sha256sum | cut -c1-8)" -days 1 \
        -extfile <(echo authorityKeyIdentifier=keyid,issuer) -out "/tmp/$cn.pem"
done
cat /tmp/chainfirst.pem /tmp/chainsecond.pem > "/etc/voa/$ID/kernel-keyring/dm-verity/x509/chain-certificate.pem"
rc=0
"$KEYRING_SETUP" .dm-verity 2>&1 | tee /tmp/keyring-setup-chain.log || rc=$?
[[ "$rc" -eq 65 ]]
grep -F "'/etc/voa/$ID/kernel-keyring/dm-verity/x509/chain-certificate.pem' contains more than one certificate, ignoring." /tmp/keyring-setup-chain.log >/dev/null
(! keyctl list %:.dm-verity | grep -F 'chainfirst' >/dev/null)
(! keyctl list %:.dm-verity | grep -F 'chainsecond' >/dev/null)
grep -E ' +08070000 +0 +0 +keyring +\.dm-verity: 9$' /proc/keys

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
