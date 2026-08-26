#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
#
# Note that unlike the .dm-verity and .bpf keyrings the kernel never seals
# .fs-verity. Only systemd-keyring-setup does. It enrolled the certificate from
# the VOA hierarchy at boot and sealed the keyring like the others, so only
# certificates chaining to it can be added later, also via a credential.
set -eux
set -o pipefail

KEYRING_SETUP=/usr/lib/systemd/systemd-keyring-setup

# Everything up to the keyring gate below needs no kernel keyring support
[[ "$(systemctl show -P ActiveState systemd-keyring-setup.service)" == "active" ]]
[[ "$(systemctl show -P Result systemd-keyring-setup.service)" == "success" ]]
[[ "$(systemctl show -P ExecMainStatus systemd-keyring-setup.service)" == "0" ]]

# Rejected credential names are ignored and do not fail the run
systemd-run --pipe --wait \
    --property LoadCredential=keyring-setup.fs-verityX.foo:/usr/share/mkosi.crt \
    --property LoadCredential=keyring-setup.fs-verity.Bad:/usr/share/mkosi.crt \
    --property LoadCredential=keyring-setup.bogus.foo:/usr/share/mkosi.crt \
    "$KEYRING_SETUP" .fs-verity 2>&1 | tee /tmp/keyring-setup-creds.log
grep -F "Ignoring unrecognized credential 'keyring-setup.fs-verityX.foo'" /tmp/keyring-setup-creds.log >/dev/null
grep -F "Ignoring unrecognized credential 'keyring-setup.bogus.foo'" /tmp/keyring-setup-creds.log >/dev/null
grep -F "Ignoring credential 'keyring-setup.fs-verity.Bad'" /tmp/keyring-setup-creds.log >/dev/null
(! find /run/voa \( -name 'foo-certificate.pem' -o -name 'Bad-certificate.pem' \) | grep . >/dev/null)

# keyring-setup.os overrides where credentials are placed, an invalid identifier is bad input
systemd-run --pipe --wait \
    --property SetCredential=keyring-setup.os:testos \
    --property LoadCredential=keyring-setup.fs-verity.osname:/usr/share/mkosi.crt \
    "$KEYRING_SETUP" .fs-verity
ls /run/voa/testos/kernel-keyring/fs-verity/x509/osname-certificate.pem
rc=0
systemd-run --pipe --wait --property SetCredential=keyring-setup.os:INVALID "$KEYRING_SETUP" .fs-verity || rc=$?
[[ "$rc" -eq 65 ]]

# Multiple identifiers feed the lookup, not only the placement of credentials. A distinct
# certificate, the byte-identical dedup would hide a copy of an already collected one.
mkdir -p /usr/share/voa/zweitos/kernel-keyring/fs-verity/x509
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=zwei -days 1 \
    -keyout /dev/null -out /usr/share/voa/zweitos/kernel-keyring/fs-verity/x509/zwei-certificate.pem
systemd-run --pipe --wait \
    --property SetCredential="keyring-setup.os:zweitos testos" \
    "$KEYRING_SETUP" --dry-run --no-pager --json=short .fs-verity | tee /tmp/keyring-setup-multi.json
jq -e '.[0].certificates | any(contains("/zweitos/")) and any(contains("/testos/"))' /tmp/keyring-setup-multi.json
rm -rf /usr/share/voa/zweitos

# An empty identifier list and one longer than 64 entries are bad input
rc=0
systemd-run --pipe --wait --property SetCredential=keyring-setup.os: \
    "$KEYRING_SETUP" .fs-verity 2>&1 | tee /tmp/keyring-setup-os-empty.log || rc=$?
[[ "$rc" -eq 65 ]]
grep -F "Credential keyring-setup.os is empty, ignoring." /tmp/keyring-setup-os-empty.log >/dev/null
rc=0
systemd-run --pipe --wait --property SetCredential="keyring-setup.os:$(seq -f 'os%.0f' 65 | tr '\n' ' ')" \
    "$KEYRING_SETUP" .fs-verity 2>&1 | tee /tmp/keyring-setup-os-many.log || rc=$?
[[ "$rc" -eq 65 ]]
grep -F "lists more than 64 OS identifiers, ignoring it." /tmp/keyring-setup-os-many.log >/dev/null

# An os-release ID= outside of the VOA charset disables the lookup, reported once, the run still fails
printf 'ID=Debian\n' >/tmp/bad-os-release
rc=0
systemd-run --pipe --wait --property BindReadOnlyPaths=/tmp/bad-os-release:/etc/os-release \
    "$KEYRING_SETUP" .fs-verity 2>&1 | tee /tmp/keyring-setup-badid.log || rc=$?
[[ "$rc" -eq 1 ]]
grep -F "Failed to determine the OS identifier from os-release, enrolling nothing" /tmp/keyring-setup-badid.log >/dev/null
(! grep -F "Failed to enumerate certificates" /tmp/keyring-setup-badid.log >/dev/null)

if ! grep -E ' keyring +\.fs-verity: ' /proc/keys >/dev/null; then
    echo ".fs-verity keyring not available (CONFIG_FS_VERITY_BUILTIN_SIGNATURES?), skipping"
    exit 77
fi

# Sealed, holding the mkosi certificate
grep -E '^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +08070000 +0 +0 +keyring +\.fs-verity: 1$' /proc/keys
CN="$(openssl x509 -noout -subject -in /usr/share/mkosi.crt | sed 's/^.*CN *= *//')"
grep -E "^[0-9a-f]+ [A-Za-z-]{7} +[0-9]+ +perm +39010000 +0 +0 +asymmetri .*$CN" /proc/keys
. /etc/os-release
# Not -u: messages of the initrd run carry no _SYSTEMD_UNIT=, see the unsealed subtest
journalctl --merge -o cat -t systemd-keyring-setup |
    grep -F "Enrolled '/usr/share/voa/$ID/kernel-keyring/fs-verity/x509/mkosi-certificate.pem' into keyring .fs-verity" >/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=stranger -days 1 \
    -keyout /dev/null -out /tmp/stranger.pem
openssl x509 -in /tmp/stranger.pem -outform DER -out /tmp/stranger.der
(! keyctl padd asymmetric '' %:.fs-verity </tmp/stranger.der)
keyctl list %:.fs-verity | grep -F "$CN"

# A certificate handed over later is placed into the hierarchy, and one that is
# enrolled already is not enrolled twice
systemd-run --pipe --wait \
    --property LoadCredential=keyring-setup.fs-verity.late:/usr/share/mkosi.crt \
    "$KEYRING_SETUP" .fs-verity 2>&1 | tee /tmp/keyring-setup-late.log
(! grep -F "Enrolled '" /tmp/keyring-setup-late.log >/dev/null)
ls /run/voa/*/kernel-keyring/fs-verity/x509/late-certificate.pem
grep -E ' +08070000 +0 +0 +keyring +\.fs-verity: 1$' /proc/keys
