#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests systemd-creds make-addon and io.systemd.Credentials.MakeAddon, which wrap a plaintext credential in an
# unsigned systemd-stub addon. We check what ends up in the addon, booting it is left to the tests of the
# stub.

for tool in objcopy objdump cpio jq varlinkctl; do
    if ! command -v "$tool" >/dev/null; then
        echo "$tool not found, skipping the test"
        exit 77
    fi
done

ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)  EFI_ARCH=x64 ;;
    aarch64) EFI_ARCH=aa64 ;;
    *)       echo "No addon stub for $ARCH, skipping the test"; exit 77 ;;
esac

STUB="/usr/lib/systemd/boot/efi/addon${EFI_ARCH}.efi.stub"
if [[ ! -f "$STUB" ]]; then
    echo "$STUB not found, skipping the test"
    exit 77
fi

at_exit() {
    set +e
    [[ -n "${WORK:-}" ]] && rm -rf "$WORK"
}

trap at_exit EXIT

WORK="$(mktemp -d /var/tmp/creds-make-addon.XXXXXXXXXX)"

# Extracts the credentials cpio of the specified addon into $WORK/extract
extract() {
    rm -rf "$WORK/extract" "$WORK/creds.cpio"
    mkdir "$WORK/extract"
    objcopy --dump-section .initrd="$WORK/creds.cpio" "$1" "$WORK/scratch.efi"
    (cd "$WORK/extract" && cpio -idm --quiet <"$WORK/creds.cpio")
}

CREDS="$WORK/extract/.extra/system_credentials"

echo -n hunter2 >"$WORK/password"

# The credential name is derived from the output file name, with the addon suffix removed
systemd-creds make-addon "$WORK/password" "$WORK/mypassword.addon.efi"
[[ "$(stat -c '%a' "$WORK/mypassword.addon.efi")" == "400" ]]

# It carries the sections an addon is made of, and no signature
objdump -h "$WORK/mypassword.addon.efi" | grep '\.initrd' >/dev/null
objdump -h "$WORK/mypassword.addon.efi" | grep '\.sbat' >/dev/null
(! objdump -h "$WORK/mypassword.addon.efi" | grep '\.cmdline' >/dev/null)
(! objdump -h "$WORK/mypassword.addon.efi" | grep '\.linux' >/dev/null)
objdump -p "$WORK/mypassword.addon.efi" | grep -E '^Entry 4\s' | grep '0000000000000000 00000000' >/dev/null
objcopy --dump-section .sbat="$WORK/sbat" "$WORK/mypassword.addon.efi" "$WORK/scratch.efi"
grep '^uki-addon,1,' "$WORK/sbat" >/dev/null

# The credential is in the trusted bucket, in the same layout systemd-firstboot uses
extract "$WORK/mypassword.addon.efi"
[[ "$(stat -c '%a' "$WORK/extract/.extra")" == "555" ]]
[[ "$(stat -c '%a' "$CREDS")" == "500" ]]
[[ "$(stat -c '%a' "$CREDS/mypassword.cred")" == "400" ]]
[[ "$(find "$CREDS" -type f | wc -l)" -eq 1 ]]
cmp "$CREDS/mypassword.cred" "$WORK/password"

# Only ".addon.efi" or ".efi" is removed
systemd-creds make-addon "$WORK/password" "$WORK/other.efi"
extract "$WORK/other.efi"
cmp "$CREDS/other.cred" "$WORK/password"
systemd-creds make-addon "$WORK/password" "$WORK/plain"
extract "$WORK/plain"
cmp "$CREDS/plain.cred" "$WORK/password"
# The suffix is matched case-insensitively, as on the ESP's VFAT, the name itself keeps its case
systemd-creds make-addon "$WORK/password" "$WORK/UPPER.ADDON.EFI"
extract "$WORK/UPPER.ADDON.EFI"
cmp "$CREDS/UPPER.cred" "$WORK/password"
systemd-creds make-addon "$WORK/password" "$WORK/Mixed.Efi"
extract "$WORK/Mixed.Efi"
cmp "$CREDS/Mixed.cred" "$WORK/password"

# --name= overrides the name, and stdin/stdout work
systemd-creds make-addon --name=foo.bar "$WORK/password" "$WORK/whatever.addon.efi"
extract "$WORK/whatever.addon.efi"
cmp "$CREDS/foo.bar.cred" "$WORK/password"
systemd-creds make-addon --name=foo.bar - - <"$WORK/password" >"$WORK/stdout.addon.efi"
cmp "$WORK/stdout.addon.efi" "$WORK/whatever.addon.efi"

# Binary data survives
dd if=/dev/urandom of="$WORK/binary" bs=1024 count=64
systemd-creds make-addon "$WORK/binary" "$WORK/binary.addon.efi"
extract "$WORK/binary.addon.efi"
cmp "$CREDS/binary.cred" "$WORK/binary"

# An existing file is replaced
systemd-creds make-addon "$WORK/binary" "$WORK/mypassword.addon.efi"
extract "$WORK/mypassword.addon.efi"
cmp "$CREDS/mypassword.cred" "$WORK/binary"

# What is refused
(! systemd-creds make-addon "$WORK/password" -)
(! systemd-creds make-addon --name= "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon "$WORK/password" "$WORK/bad:name.addon.efi")
(! systemd-creds make-addon "$WORK/password" "$WORK/")
(! systemd-creds make-addon "$WORK/password")
(! systemd-creds make-addon --with-key=host "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon -T "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon --uid=0 "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon --timestamp=now "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon --not-after=+1d "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon --tpm2-device=/dev/null "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon --pretty "$WORK/password" "$WORK/refused.addon.efi")
(! systemd-creds make-addon /nonexistent "$WORK/refused.addon.efi")
(! SYSTEMD_ADDON_STUB=/nonexistent systemd-creds make-addon "$WORK/password" "$WORK/refused.addon.efi")
# A stub that is an addon already is refused
(! SYSTEMD_ADDON_STUB="$WORK/whatever.addon.efi" systemd-creds make-addon "$WORK/password" "$WORK/refused.addon.efi")
# Names whose "<name>.cred" cpio entry would exceed NAME_MAX are refused
LONGNAME="$(printf 'a%.0s' {1..251})"
(! systemd-creds make-addon --name="$LONGNAME" "$WORK/password" "$WORK/refused.addon.efi")
[[ ! -e "$WORK/refused.addon.efi" ]]
systemd-creds make-addon --name="${LONGNAME:1}" "$WORK/password" - >/dev/null

# Too large for a credential
truncate -s 2M "$WORK/large"
(! systemd-creds make-addon "$WORK/large" "$WORK/refused.addon.efi")
[[ ! -e "$WORK/refused.addon.efi" ]]

# The same via Varlink, which results in the very same addon
SOCKET=/run/systemd/io.systemd.Credentials
varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon '{"name":"foo.bar","text":"hunter2"}' |
    jq -r .blob | base64 -d >"$WORK/varlink.addon.efi"
cmp "$WORK/varlink.addon.efi" "$WORK/whatever.addon.efi"
varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon "{\"name\":\"binary\",\"data\":\"$(base64 -w0 <"$WORK/binary")\"}" |
    jq -r .blob | base64 -d >"$WORK/varlink-binary.addon.efi"
cmp "$WORK/varlink-binary.addon.efi" "$WORK/binary.addon.efi"

# Also for unprivileged clients
run0 -u testuser --pipe varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon '{"name":"foo.bar","text":"hunter2"}' |
    jq -r .blob | base64 -d >"$WORK/varlink-unpriv.addon.efi"
cmp "$WORK/varlink-unpriv.addon.efi" "$WORK/whatever.addon.efi"

(! varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon '{"name":"foo"}')
(! varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon '{"name":"foo","text":"hunter2","data":"aHVudGVyMg=="}')
(! varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon '{"name":"bad/name","text":"hunter2"}')
(! varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon '{"name":"","text":"hunter2"}')
(! varlinkctl call "$SOCKET" io.systemd.Credentials.MakeAddon "{\"name\":\"$LONGNAME\",\"text\":\"hunter2\"}")
