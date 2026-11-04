#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

# Tests systemd-firstboot --addon=, which writes the settings as a (for now unsigned) systemd-stub addon
# into the ESP of an image, without mounting it. We check what ends up in the image, booting it is left to
# the tests of the stub.

if ! command -v systemd-firstboot >/dev/null; then
    echo "systemd-firstboot not found, skipping the test"
    exit 77
fi

for tool in systemd-repart mcopy mdir mmd objcopy objdump cpio jq sfdisk openssl; do
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

WORK="$(mktemp -d /var/tmp/firstboot-addon.XXXXXXXXXX)"
DEFS="$WORK/defs"
IMAGE="$WORK/image.raw"
mkdir -p "$DEFS"

# An image with an ESP and a root partition, nothing in them, as the root file system is never looked at
cat >"$DEFS/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=16M
SizeMaxBytes=16M
EOF

cat >"$DEFS/20-root.conf" <<EOF
[Partition]
Type=root
Format=ext4
SizeMinBytes=16M
SizeMaxBytes=16M
EOF

systemd-repart --empty=create --size=auto --dry-run=no --offline=yes --definitions="$DEFS" "$IMAGE"

ESP_START="$(sfdisk --json "$IMAGE" | jq -r '.partitiontable.partitions[] | select(.type == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") | .start')"
ESP_OFFSET=$((ESP_START * 512))
NODE="$IMAGE@@$ESP_OFFSET"

# Something to provision as keys
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=customer -days 2 \
        -keyout "$WORK/customer.key" -out "$WORK/customer.crt"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj /CN=second -days 2 \
        -keyout "$WORK/second.key" -out "$WORK/second.crt"

# shellcheck disable=SC2016
HASHED='$y$j9T$CUiPhA.Hy6ijhLYMo9YTD0$hxJc7ahdrOLojG3Ltd2SE0M02ZU5ZiUoGMNLyr3SWO0'

systemd-firstboot \
    --image="$IMAGE" \
    --addon=customer \
    --hostname=customerbox \
    --locale=C.UTF-8 \
    --locale-messages=C.UTF-8 \
    --keymap=us \
    --timezone=Europe/Berlin \
    --machine-tags=foo:bar \
    --machine-id=0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c \
    --root-password-hashed="$HASHED" \
    --root-shell=/bin/sh \
    --kernel-command-line='firstboot.addon=1' \
    --key=dm-verity:"$WORK/customer.crt" \
    --key=fs-verity:other="$WORK/second.crt"

# The addon landed at the expected place, and nowhere else
mdir -i "$NODE" ::/loader/addons/ | grep 'customer.addon.efi' >/dev/null
[[ "$(mdir -i "$NODE" -b ::/loader/addons/ | wc -l)" -eq 1 ]]
mcopy -n -i "$NODE" ::/loader/addons/customer.addon.efi "$WORK/customer.addon.efi"

# It carries the sections an addon is made of, and no signature
objdump -h "$WORK/customer.addon.efi" | grep '\.cmdline' >/dev/null
objdump -h "$WORK/customer.addon.efi" | grep '\.initrd' >/dev/null
objdump -h "$WORK/customer.addon.efi" | grep '\.sbat' >/dev/null
objdump -p "$WORK/customer.addon.efi" | grep -E '^Entry 4\s' | grep '0000000000000000 00000000' >/dev/null

objcopy --dump-section .cmdline="$WORK/cmdline" \
        --dump-section .initrd="$WORK/creds.cpio" \
        --dump-section .sbat="$WORK/sbat" \
        "$WORK/customer.addon.efi" "$WORK/scratch.efi"
[[ "$(cat "$WORK/cmdline")" == "firstboot.addon=1" ]]
grep -q '^uki-addon,1,' "$WORK/sbat"

# The credentials in the cpio are the ones the settings map to, in the trusted bucket
mkdir "$WORK/extract"
(cd "$WORK/extract" && cpio -idm --quiet <"$WORK/creds.cpio")
CREDS="$WORK/extract/.extra/system_credentials"
[[ "$(stat -c '%a' "$CREDS")" == "500" ]]
[[ "$(cat "$CREDS/firstboot.hostname.cred")" == "customerbox" ]]
[[ "$(cat "$CREDS/firstboot.locale.cred")" == "C.UTF-8" ]]
[[ "$(cat "$CREDS/firstboot.locale-messages.cred")" == "C.UTF-8" ]]
[[ "$(cat "$CREDS/firstboot.keymap.cred")" == "us" ]]
[[ "$(cat "$CREDS/firstboot.timezone.cred")" == "Europe/Berlin" ]]
[[ "$(cat "$CREDS/firstboot.machine-tags.cred")" == "bar:foo" ]]
[[ "$(cat "$CREDS/system.machine_id.cred")" == "0e1d84a8a1d84c6e9b2d2f0f8f1a2b3c" ]]
[[ "$(cat "$CREDS/passwd.hashed-password.root.cred")" == "$HASHED" ]]
[[ "$(cat "$CREDS/passwd.shell.root.cred")" == "/bin/sh" ]]
cmp "$CREDS/keyring-setup.dm-verity.customer.cred" "$WORK/customer.crt"
cmp "$CREDS/keyring-setup.fs-verity.other.cred" "$WORK/second.crt"
[[ "$(stat -c '%a' "$CREDS/keyring-setup.dm-verity.customer.cred")" == "400" ]]
[[ "$(find "$CREDS" -type f | wc -l)" -eq 11 ]]

# A plaintext password is hashed before it ends up in the addon, and writing again replaces the addon
systemd-firstboot --image="$IMAGE" --addon=customer --root-password=hunter2
mcopy -o -n -i "$NODE" ::/loader/addons/customer.addon.efi "$WORK/customer2.addon.efi"
objcopy --dump-section .initrd="$WORK/creds2.cpio" "$WORK/customer2.addon.efi" "$WORK/scratch.efi"
rm -rf "$WORK/extract"
mkdir "$WORK/extract"
(cd "$WORK/extract" && cpio -idm --quiet <"$WORK/creds2.cpio")
[[ "$(find "$CREDS" -type f | wc -l)" -eq 1 ]]
grep -q '^\$' "$CREDS/passwd.hashed-password.root.cred"
grep -qv 'hunter2' "$CREDS/passwd.hashed-password.root.cred"
(! objdump -h "$WORK/customer2.addon.efi" | grep '\.cmdline' >/dev/null)

# A second addon lives next to the first
systemd-firstboot --image="$IMAGE" --addon=other --hostname=otherbox
[[ "$(mdir -i "$NODE" -b ::/loader/addons/ | wc -l)" -eq 2 ]]

# A key path containing '=' is not mistaken for NAME=PATH
mkdir "$WORK/a=b"
cp "$WORK/customer.crt" "$WORK/a=b/customer.crt"
systemd-firstboot --image="$IMAGE" --addon=third --key=bpf:"$WORK/a=b/customer.crt"
mcopy -o -n -i "$NODE" ::/loader/addons/third.addon.efi "$WORK/third.addon.efi"
objcopy --dump-section .initrd="$WORK/creds3.cpio" "$WORK/third.addon.efi" "$WORK/scratch.efi"
rm -rf "$WORK/extract"
mkdir "$WORK/extract"
(cd "$WORK/extract" && cpio -idm --quiet <"$WORK/creds3.cpio")
cmp "$CREDS/keyring-setup.bpf.customer.cred" "$WORK/customer.crt"

# What is refused
(! systemd-firstboot --addon=customer --hostname=foo)
(! systemd-firstboot --image="$IMAGE" --addon=customer --prompt-hostname)
(! systemd-firstboot --image="$IMAGE" --addon=customer --copy-timezone)
(! systemd-firstboot --image="$IMAGE" --addon=customer --hostname=foo --force)
(! systemd-firstboot --image="$IMAGE" --addon=customer --hostname=foo --reset)
(! systemd-firstboot --image="$IMAGE" --addon=customer --delete-root-password)
(! systemd-firstboot --image="$IMAGE" --addon=customer)
(! systemd-firstboot --image="$IMAGE" --addon='../customer' --hostname=foo)
(! systemd-firstboot --image="$IMAGE" --addon=customer --key=dm-verity:/dev/null)
(! systemd-firstboot --image="$IMAGE" --addon=customer --key="$WORK/customer.crt")
(! systemd-firstboot --image="$IMAGE" --addon=customer --key=bad:"$WORK/customer.crt")
(! systemd-firstboot --image="$IMAGE" --addon=customer --key=dm-verity:Bad="$WORK/customer.crt")
(! systemd-firstboot --image="$IMAGE" --addon='cust:omer' --hostname=foo)
(! systemd-firstboot --image="$IMAGE" --addon=customer --key=dm-verity:="$WORK/customer.crt")
(! systemd-firstboot --image="$IMAGE" --addon=customer --key=dm-verity:)
cp "$WORK/customer.crt" "$WORK/.hidden"
(! systemd-firstboot --image="$IMAGE" --addon=customer --key=dm-verity:"$WORK/.hidden")
(! systemd-firstboot --image="$IMAGE" --key=dm-verity:"$WORK/customer.crt")
# An empty kernel command line is not a setting either
(! systemd-firstboot --image="$IMAGE" --addon=customer --kernel-command-line=)
# The locales are at least checked for syntax
(! systemd-firstboot --image="$IMAGE" --addon=customer --locale='not a locale')
(! systemd-firstboot --image="$IMAGE" --addon=customer --locale-messages='not a locale')
# mtools cannot handle '@@' in the image path
cp "$IMAGE" "$WORK/we@@ird.raw"
(! systemd-firstboot --image="$WORK/we@@ird.raw" --addon=customer --hostname=foo)
# A stub that is an addon already is refused
(! SYSTEMD_ADDON_STUB="$WORK/customer.addon.efi" systemd-firstboot --image="$IMAGE" --addon=customer --hostname=foo)

# An image without an ESP
rm -f "$DEFS/10-esp.conf"
rm -f "$IMAGE"
systemd-repart --empty=create --size=auto --dry-run=no --offline=yes --definitions="$DEFS" "$IMAGE"
(! systemd-firstboot --image="$IMAGE" --addon=customer --hostname=foo)

# With an XBOOTLDR partition the addon goes there, as that is where the UKIs, and hence the stub looking for
# addons, live
cat >"$DEFS/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
SizeMinBytes=16M
SizeMaxBytes=16M
EOF

cat >"$DEFS/15-xbootldr.conf" <<EOF
[Partition]
Type=xbootldr
Format=vfat
SizeMinBytes=16M
SizeMaxBytes=16M
EOF

rm -f "$IMAGE"
systemd-repart --empty=create --size=auto --dry-run=no --offline=yes --definitions="$DEFS" "$IMAGE"
ESP_START="$(sfdisk --json "$IMAGE" | jq -r '.partitiontable.partitions[] | select(.type == "C12A7328-F81F-11D2-BA4B-00A0C93EC93B") | .start')"
XBOOTLDR_START="$(sfdisk --json "$IMAGE" | jq -r '.partitiontable.partitions[] | select(.type == "BC13C2FF-59E6-4262-A352-B275FD6F7172") | .start')"

systemd-firstboot --image="$IMAGE" --addon=customer --hostname=customerbox
mdir -i "$IMAGE@@$((XBOOTLDR_START * 512))" ::/loader/addons/ | grep 'customer.addon.efi' >/dev/null
(! mdir -i "$IMAGE@@$((ESP_START * 512))" ::/loader/addons/ 2>/dev/null)
