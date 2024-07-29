#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Check that the /sbin/mount.ddi helper works
dir="/tmp/mounthelper.$RANDOM"
mount -t ddi "$MINIMAL_IMAGE.gpt" "$dir" -o ro,X-mount.mkdir,discard
umount -R "$dir"

# Test systemd-repart --make-ddi=:
if [[ -z "${OPENSSL_CONFIG:?}" ]] || ! command -v mksquashfs &>/dev/null; then
    echo "Skipping --make-ddi= tests"
    exit 0
fi

openssl req -config "$OPENSSL_CONFIG" -subj="/CN=waldo" \
            -x509 -sha256 -nodes -days 365 -newkey rsa:4096 \
            -keyout /tmp/test-50-privkey.key -out /tmp/test-50-cert.crt
mkdir -p /tmp/test-50-confext/etc/extension-release.d/
echo "foobar50" >/tmp/test-50-confext/etc/waldo
{
    grep -e '^\(ID\|VERSION_ID\)=' /etc/os-release
    echo IMAGE_ID=waldo
    echo IMAGE_VERSION=7
} >/tmp/test-50-confext/etc/extension-release.d/extension-release.waldo
mkdir -p /run/confexts

SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
    systemd-repart -C \
                   -s /tmp/test-50-confext \
                   --certificate=/tmp/test-50-cert.crt \
                   --private-key=/tmp/test-50-privkey.key \
                   /run/confexts/waldo.confext.raw
rm -rf /tmp/test-50-confext

mkdir -p /run/verity.d
cp /tmp/test-50-cert.crt /run/verity.d/
systemd-dissect --mtree /run/confexts/waldo.confext.raw

systemd-confext refresh
test "$(</etc/waldo)" = foobar50
rm /run/confexts/waldo.confext.raw
systemd-confext refresh
test ! -f /etc/waldo

mkdir -p /tmp/test-50-sysext/usr/lib/extension-release.d/
# Make sure the sysext is big enough to not fit in the minimum partition size of repart so we know the
# Minimize= logic is working.
truncate --size=50M /tmp/test-50-sysext/usr/waldo
{
    grep -e '^\(ID\|VERSION_ID\)=' /etc/os-release
    echo IMAGE_ID=waldo
    echo IMAGE_VERSION=7
} >/tmp/test-50-sysext/usr/lib/extension-release.d/extension-release.waldo
mkdir -p /run/extensions

SYSTEMD_REPART_OVERRIDE_FSTYPE=squashfs \
    systemd-repart -S \
                   -s /tmp/test-50-sysext \
                   --certificate=/tmp/test-50-cert.crt \
                   --private-key=/tmp/test-50-privkey.key \
                   /run/extensions/waldo.sysext.raw

systemd-dissect --mtree /run/extensions/waldo.sysext.raw
systemd-sysext refresh
test -f /usr/waldo
rm /run/verity.d/test-50-cert.crt /run/extensions/waldo.sysext.raw /tmp/test-50-cert.crt /tmp/test-50-privkey.key
systemd-sysext refresh
test ! -f /usr/waldo
